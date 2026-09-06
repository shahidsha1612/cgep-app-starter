# Capstone Write-up Log

Running record of the CGE-P capstone work on `cgep-app-starter` (Acme Health
patient intake API). Kept as raw material for building tutorials/guides later -
not a polished deliverable itself.

## Framework decision

Chose **SOC 2 Trust Services Criteria** as the primary framework (over HIPAA and
CMMC L2). See `FRAMEWORKS.md` for the full comparison.

## Step zero - confirm the starter deploys

Deployed the unmodified starter to a personal AWS sandbox account (IAM user
`terraform-lab`) using two named profiles, `sandbox` / `sandbox2`, configured
with static access keys in `~/.aws/credentials` (not SSO).

Verified via `terraform output` (all six required values present) and a smoke
test:
```
curl -X POST "$API_URL" -d '{"patient_id":"P-0001","fields":{"reason":"smoke-test"}}'
→ {"submission_id": "...", "status": "received"}
```

**Gotcha:** `AWS_PROFILE` set in one terminal command doesn't persist to the
next command in some tool/session setups - always confirm it's set
(`echo $env:AWS_PROFILE` in PowerShell) in the *same* window you run
`terraform plan`/`apply` in, or you'll hit `No valid credential sources found`
even with valid keys sitting in `~/.aws/credentials`.

## Gap remediation - Terraform (Layer 1 of 4)

Chose to close 6 of the 8 named gaps in `GAPS.md`, mapped to SOC 2 controls:

| Gap | Fix | SOC 2 control |
|---|---|---|
| GAP-01 | S3 SSE-KMS with a customer CMK (`aws_kms_key.phi`) | CC6.1 |
| GAP-02 | DynamoDB `server_side_encryption` under the same CMK | CC6.1 |
| GAP-03 | S3 bucket policy denying `aws:SecureTransport = false` | CC6.7 |
| GAP-04 | S3 versioning enabled | A1.2 |
| GAP-05 | Lambda `vpc_config` into private subnets + gateway endpoints (S3, DynamoDB) + dedicated security group (egress 443 only) + `AWSLambdaVPCAccessExecutionRole` attachment | CC6.6 |
| GAP-07 | IAM inline policy narrowed from `dynamodb:*`/`s3:*` to `dynamodb:PutItem`/`s3:PutObject` + minimum KMS actions, matching exactly what `handler.py` does | CC6.3 |

Left open (documented, not coded): GAP-06 (no DLQ/concurrency/X-Ray) and
GAP-08 (no API Gateway access logging/throttling/WAF) - both map to CC7.2.
Decision: revisit before final OSCAL write-up, either close them or document
as accepted residual risk.

**Design choice worth remembering:** moving the Lambda into private subnets
with no NAT gateway meant it had no route to the internet - including to S3
and DynamoDB, which it needs. Solved with VPC **gateway endpoints** (free,
no NAT cost) rather than a NAT gateway, since S3 and DynamoDB both support the
gateway endpoint type. Interface endpoints / NAT would have been the fallback
for any other AWS service without gateway-endpoint support.

**Bug hit during apply:** `aws_security_group.lambda`'s `description` field
used a non-ASCII dash character. AWS's `CreateSecurityGroup` API rejects any
non-ASCII character in that field:
```
InvalidParameterValue: Value (...) for parameter GroupDescription is invalid.
Character sets beyond ASCII are not supported.
```
Fix: replace em dashes with plain hyphens in any AWS-facing string field
(tags are fine with Unicode; certain API string fields like SG descriptions
are not). Worth a general rule: keep AWS resource description/name fields
plain-ASCII by default.

**Apply ran in two passes** - first pass applied everything up to the broken
security group and stopped there (Terraform still commits independently
resource by resource); second pass, after the ASCII fix, created the security
group and finished the one resource that depended on it (the Lambda's
`vpc_config` update). Total across both: 12 added, 3 changed, 0 destroyed -
matching the original plan exactly.

## Verification after deploy

```
terraform state list   # confirms all new resources tracked
curl -X POST "$API_URL" -d '{"patient_id":"P-0002","fields":{"reason":"post-remediation smoke-test"}}'
→ HTTP 200, {"submission_id": "...", "status": "received"}
```
Confirms the Lambda works correctly from inside the VPC, through the gateway
endpoints, with the tightened IAM policy and KMS encryption in place - no
regression in the actual API behavior.

## Deliverables produced so far

- `closing-meeting/closed-gaps.md` - plain markdown/table record, for git diffing.
- `closing-meeting/closed-gaps-stakeholder.html` - non-technical version, plain-language metaphors only (locks/keys/private rooms), no AWS or SOC 2 jargon, for a non-technical stakeholder audience.

## Policy suite - Rego/OPA (Layer 2 of 4)

Wrote 6 Rego policies in `policy/`, one per closed gap, each with a `METADATA`
header tagging the SOC 2 control it enforces (per `FRAMEWORKS.md`'s format).
Tooling: Conftest 0.69.0 / OPA 1.19 (Rego v1 syntax - policies use
`import rego.v1` and `contains`/`if` rule syntax).

| Policy | Gap | Control |
|---|---|---|
| `s3_encryption.rego` | GAP-01 | CC6.1 |
| `dynamodb_encryption.rego` | GAP-02 | CC6.1 |
| `s3_tls_only.rego` | GAP-03 | CC6.7 |
| `s3_versioning.rego` | GAP-04 | A1.2 |
| `lambda_vpc.rego` | GAP-05 | CC6.6 |
| `lambda_iam_least_privilege.rego` | GAP-07 | CC6.3 |

**Gotcha:** Conftest only evaluates policies in the `main` namespace by
default. Since these are namespaced `compliance.soc2.*` (matching
`FRAMEWORKS.md`'s convention), every run needs `--all-namespaces`, or
Conftest silently reports `0 tests, 0 passed`.

**Gotcha:** Terraform's plan JSON represents every nested `block { ... }`
(even ones that only ever appear once, like
`apply_server_side_encryption_by_default`) as a **list** containing one
object, not a bare object. First draft of `s3_encryption.rego` referenced
`...apply_server_side_encryption_by_default.sse_algorithm` and silently
failed (the gap looked "open" even though it was fixed) until changed to
`...apply_server_side_encryption_by_default[_].sse_algorithm`. Worth
checking the actual `terraform show -json` output for a resource's shape
before assuming a schema.

**Verification performed:**
- Ran the full suite against the live, remediated plan: `6 tests, 6 passed`.
- Proved "fails closed": temporarily reverted GAP-07's IAM policy to
  `dynamodb:*`/`s3:*` in `main.tf`, generated a plan (never applied), and
  confirmed `lambda_iam_least_privilege.rego` failed the plan by name for
  both wildcard actions. Reverted the file back to the least-privilege
  version afterward and re-ran `terraform validate` to confirm nothing was
  left broken.

## Still to do (remaining 2 of 4 capstone layers)

1. **GitHub Actions pipeline** - plan → Conftest gate → apply → sign → upload evidence.
2. **OSCAL component-definition.json** - control-implementation entries citing a SOC 2 TSC catalog (or NIST 800-53 mapping, per FRAMEWORKS.md's note that AICPA has no official OSCAL catalog), covering the 6 closed gaps plus a documented stance on GAP-06/GAP-08.
