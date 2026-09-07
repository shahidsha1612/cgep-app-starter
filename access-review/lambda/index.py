"""
Acme Health — Automated Access Review.

Audits the CURRENT AWS account for common IAM / S3 security gaps, writes a
timestamped CSV report to S3, asks Bedrock for a plain-English executive
summary, and (optionally) emails that summary via SES.

Findings are intentionally the ones that drive most cloud incidents and that
auditors sample for SOC 2 / ISO 27001:
    - root account: MFA missing, access keys present, recent usage
    - IAM users: console access without MFA
    - access keys: stale (not rotated in >90 days) or never used
    - account password policy: missing or weak
    - S3 buckets: public access not fully blocked, no default encryption

Read-only. The Lambda's role is SecurityAudit + a scoped inline policy; it
never mutates the account.
"""

import csv
import datetime as dt
import io
import json
import os

import boto3
from botocore.exceptions import ClientError

REPORT_BUCKET = os.environ["REPORT_BUCKET"]
RECIPIENT_EMAIL = os.environ.get("RECIPIENT_EMAIL", "")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "") or RECIPIENT_EMAIL
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "")
ENABLE_EMAIL = os.environ.get("ENABLE_EMAIL", "false").lower() == "true"
ENABLE_BEDROCK = os.environ.get("ENABLE_BEDROCK", "true").lower() == "true"

STALE_KEY_DAYS = 90

iam = boto3.client("iam")
s3 = boto3.client("s3")

NOW = None  # set per-invocation in handler so tests can freeze it


def _now():
    return NOW or dt.datetime.now(dt.timezone.utc)


def _finding(severity, category, resource, finding, recommendation):
    return {
        "severity": severity,
        "category": category,
        "resource": resource,
        "finding": finding,
        "recommendation": recommendation,
    }


def _parse_ts(value):
    """Parse an IAM credential-report timestamp; return None for N/A values."""
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _age_days(value):
    ts = _parse_ts(value)
    if ts is None:
        return None
    return (_now() - ts).days


# ---------------------------------------------------------------------------
# IAM checks (driven by the credential report)
# ---------------------------------------------------------------------------

def _get_credential_report():
    """Generate (if needed) and fetch the IAM credential report as dict rows."""
    for _ in range(6):
        try:
            resp = iam.get_credential_report()
            content = resp["Content"].decode("utf-8")
            return list(csv.DictReader(io.StringIO(content)))
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ReportNotPresent", "ReportInProgress", "ReportExpired"):
                iam.generate_credential_report()
                continue
            raise
    return []


def check_iam(findings):
    rows = _get_credential_report()

    for row in rows:
        user = row["user"]
        is_root = user == "<root_account>"

        mfa_active = row.get("mfa_active") == "true"
        password_enabled = row.get("password_enabled") == "true"

        if is_root:
            if not mfa_active:
                findings.append(_finding(
                    "CRITICAL", "IAM", "root account",
                    "Root account does not have MFA enabled.",
                    "Enable a hardware or virtual MFA device on the root user immediately.",
                ))
            if row.get("access_key_1_active") == "true" or row.get("access_key_2_active") == "true":
                findings.append(_finding(
                    "CRITICAL", "IAM", "root account",
                    "Root account has active access keys.",
                    "Delete all root access keys; use IAM roles/users for programmatic access.",
                ))
            root_used = _age_days(row.get("password_last_used"))
            if root_used is not None and root_used <= 7:
                findings.append(_finding(
                    "HIGH", "IAM", "root account",
                    f"Root account was used {root_used} day(s) ago.",
                    "Avoid using root for daily operations; lock it away after setup.",
                ))
            continue

        # Console user without MFA
        if password_enabled and not mfa_active:
            findings.append(_finding(
                "HIGH", "IAM", f"user/{user}",
                "IAM user has console access but no MFA.",
                "Enforce MFA for all users with console access.",
            ))

        # Stale / unused access keys
        for idx in ("1", "2"):
            if row.get(f"access_key_{idx}_active") != "true":
                continue
            rotated = _age_days(row.get(f"access_key_{idx}_last_rotated"))
            last_used = row.get(f"access_key_{idx}_last_used_date")
            if rotated is not None and rotated > STALE_KEY_DAYS:
                findings.append(_finding(
                    "MEDIUM", "IAM", f"user/{user}",
                    f"Access key {idx} has not been rotated in {rotated} days.",
                    f"Rotate access keys at least every {STALE_KEY_DAYS} days; delete unused keys.",
                ))
            if _parse_ts(last_used) is None and rotated is not None and rotated > STALE_KEY_DAYS:
                findings.append(_finding(
                    "MEDIUM", "IAM", f"user/{user}",
                    f"Access key {idx} is active but appears never to have been used.",
                    "Delete unused access keys to reduce credential exposure.",
                ))


def check_password_policy(findings):
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            findings.append(_finding(
                "HIGH", "IAM", "account password policy",
                "No IAM account password policy is configured.",
                "Set a password policy: min length >=14, complexity, reuse prevention, expiry.",
            ))
            return
        raise

    if policy.get("MinimumPasswordLength", 0) < 14:
        findings.append(_finding(
            "MEDIUM", "IAM", "account password policy",
            f"Minimum password length is {policy.get('MinimumPasswordLength', 0)} (recommended >= 14).",
            "Increase the minimum password length to at least 14 characters.",
        ))
    if not policy.get("RequireSymbols") or not policy.get("RequireNumbers"):
        findings.append(_finding(
            "LOW", "IAM", "account password policy",
            "Password policy does not require both symbols and numbers.",
            "Require symbols, numbers, and mixed case in passwords.",
        ))


# ---------------------------------------------------------------------------
# S3 checks
# ---------------------------------------------------------------------------

def check_s3(findings):
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError:
        return

    for b in buckets:
        name = b["Name"]

        # Public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            fully_blocked = all([
                pab.get("BlockPublicAcls"), pab.get("IgnorePublicAcls"),
                pab.get("BlockPublicPolicy"), pab.get("RestrictPublicBuckets"),
            ])
        except ClientError as e:
            if e.response["Error"]["Code"] in ("NoSuchPublicAccessBlockConfiguration", "AccessDenied"):
                fully_blocked = False
            else:
                fully_blocked = False
        if not fully_blocked:
            findings.append(_finding(
                "HIGH", "S3", f"bucket/{name}",
                "Bucket does not have all four Block Public Access settings enabled.",
                "Enable account- and bucket-level Block Public Access on all four settings.",
            ))

        # Default encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(_finding(
                    "MEDIUM", "S3", f"bucket/{name}",
                    "Bucket has no default server-side encryption configured.",
                    "Enable default encryption (SSE-S3 or SSE-KMS) on the bucket.",
                ))


# ---------------------------------------------------------------------------
# IAM Access Analyzer — external / public access
# ---------------------------------------------------------------------------

def check_access_analyzer(findings):
    aa = boto3.client("accessanalyzer")
    try:
        analyzers = aa.list_analyzers(type="ACCOUNT").get("analyzers", [])
    except ClientError:
        return
    active = [a for a in analyzers if a.get("status") == "ACTIVE"]
    if not active:
        findings.append(_finding(
            "LOW", "External Access", "IAM Access Analyzer",
            "No active account-level IAM Access Analyzer is configured.",
            "Create an account analyzer so external/public access is continuously detected.",
        ))
        return

    for analyzer in active:
        paginator = aa.get_paginator("list_findings_v2") if aa.can_paginate("list_findings_v2") \
            else None
        try:
            items = []
            token = None
            while True:
                kwargs = {"analyzerArn": analyzer["arn"],
                          "filter": {"status": {"eq": ["ACTIVE"]}}}
                if token:
                    kwargs["nextToken"] = token
                resp = aa.list_findings_v2(**kwargs)
                items.extend(resp.get("findings", []))
                token = resp.get("nextToken")
                if not token:
                    break
        except ClientError as e:
            print(f"Access Analyzer list_findings failed: {e}")
            continue

        for item in items:
            resource = item.get("resource", item.get("resourceType", "unknown"))
            is_public = item.get("isPublic", False)
            sev = "HIGH" if is_public else "MEDIUM"
            what = "publicly" if is_public else "with an external principal"
            findings.append(_finding(
                sev, "External Access", resource,
                f"Resource is shared {what} (IAM Access Analyzer finding).",
                "Review the resource policy; remove public/cross-account grants that aren't required.",
            ))


# ---------------------------------------------------------------------------
# Security Hub — aggregated findings from AWS security standards
# ---------------------------------------------------------------------------

SECURITYHUB_MAX = 25


def check_securityhub(findings):
    sh = boto3.client("securityhub")
    try:
        resp = sh.get_findings(
            Filters={
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                "SeverityLabel": [
                    {"Value": "CRITICAL", "Comparison": "EQUALS"},
                    {"Value": "HIGH", "Comparison": "EQUALS"},
                ],
            },
            MaxResults=SECURITYHUB_MAX,
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidAccessException", "ResourceNotFoundException"):
            # Security Hub not enabled in this account/region.
            return
        raise

    for f in resp.get("Findings", []):
        severity = f.get("Severity", {}).get("Label", "MEDIUM")
        resources = f.get("Resources", [])
        resource = resources[0]["Id"] if resources else f.get("GeneratorId", "unknown")
        findings.append(_finding(
            severity, "Security Hub", resource,
            f.get("Title", "Security Hub finding"),
            (f.get("Remediation", {}).get("Recommendation", {}) or {}).get(
                "Text", "See Security Hub console for remediation guidance."),
        ))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def build_csv(findings):
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=["severity", "category", "resource", "finding", "recommendation"]
    )
    writer.writeheader()
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
        writer.writerow(f)
    return buf.getvalue()


def _plain_summary(findings, account_id):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    lines = [
        f"AWS Access Review — account {account_id} — {_now().date().isoformat()}",
        "",
        f"{len(findings)} finding(s): "
        + ", ".join(f"{counts.get(s, 0)} {s.lower()}" for s in SEVERITY_ORDER) + ".",
        "",
        "Top findings:",
    ]
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))[:8]:
        lines.append(f"  [{f['severity']}] {f['resource']}: {f['finding']}")
    return "\n".join(lines)


def bedrock_summary(findings, account_id):
    if not ENABLE_BEDROCK or not BEDROCK_MODEL_ID or not findings:
        return _plain_summary(findings, account_id)
    try:
        bedrock = boto3.client("bedrock-runtime")
        payload = json.dumps({f["severity"] + " " + f["resource"]: f["finding"] for f in findings})
        prompt = (
            "You are a cloud security analyst. Write a concise executive summary "
            "(under 200 words) of the following AWS access-review findings for account "
            f"{account_id}. Lead with the most critical risks, group by theme, and end "
            "with the top 3 prioritised remediation actions. Findings JSON:\n" + payload
        )
        resp = bedrock.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 800,
                "messages": [{"role": "user", "content": prompt}],
            }),
        )
        body = json.loads(resp["body"].read())
        return body["content"][0]["text"]
    except Exception as e:  # noqa: BLE001 - narrative is best-effort
        print(f"Bedrock summary failed, using plain summary: {e}")
        return _plain_summary(findings, account_id)


def send_email(subject, summary, csv_body):
    if not ENABLE_EMAIL:
        print("Email disabled (ENABLE_EMAIL=false); skipping send.")
        return
    if not RECIPIENT_EMAIL:
        print("No RECIPIENT_EMAIL set; skipping send.")
        return
    ses = boto3.client("ses")
    ses.send_email(
        Source=SENDER_EMAIL,
        Destination={"ToAddresses": [RECIPIENT_EMAIL]},
        Message={
            "Subject": {"Data": subject},
            "Body": {"Text": {"Data": summary + "\n\n--- Full CSV report attached in S3 ---"}},
        },
    )
    print(f"Emailed report summary to {RECIPIENT_EMAIL}")


def handler(event, context):
    global NOW
    NOW = dt.datetime.now(dt.timezone.utc)

    account_id = boto3.client("sts").get_caller_identity()["Account"]
    findings = []

    for check in (check_iam, check_password_policy, check_s3,
                  check_access_analyzer, check_securityhub):
        try:
            check(findings)
        except Exception as e:  # noqa: BLE001 - one check failing shouldn't kill the run
            print(f"Check {check.__name__} failed: {e}")

    csv_body = build_csv(findings)
    summary = bedrock_summary(findings, account_id)

    key = f"reports/{NOW.strftime('%Y/%m/%d')}/access-review-{NOW.strftime('%Y%m%dT%H%M%SZ')}.csv"
    s3.put_object(
        Bucket=REPORT_BUCKET, Key=key, Body=csv_body.encode("utf-8"),
        ContentType="text/csv", ServerSideEncryption="AES256",
    )
    print(f"Wrote report to s3://{REPORT_BUCKET}/{key} ({len(findings)} findings)")

    subject = f"AWS Access Review — {account_id} — {len(findings)} findings"
    send_email(subject, summary, csv_body)

    return {
        "account_id": account_id,
        "finding_count": len(findings),
        "report_s3_key": key,
        "summary": summary,
    }
