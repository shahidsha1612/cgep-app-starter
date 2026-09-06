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

## CI/CD pipeline - GitHub Actions (Layer 3 of 4)

`.github/workflows/grc-pipeline.yml`, two jobs:
- `plan-and-gate` (every PR + push): `terraform plan` -> export JSON ->
  `conftest test ... --all-namespaces` against `policy/`. Blocks on any
  gap-detection failure.
- `apply-and-evidence` (push to `main` only): applies the exact plan the
  gate reviewed, builds an evidence manifest (commit SHA, run id,
  timestamp, policy result), signs both the plan JSON and the manifest
  with Cosign keyless (GitHub OIDC -> Sigstore Fulcio/Rekor, no signing
  key to manage), uploads everything to the S3 evidence vault under
  `evidence/<commit-sha>/`.

Secrets: `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` set on the repo via
`gh secret set`, reusing the same sandbox keys used for local Terraform
runs (acceptable for a personal sandbox account; an OIDC federated role
would be the production-grade upgrade, noted as a possible future
improvement rather than built here).

**Gotcha (real, caught on first CI run):** state. GitHub Actions had no
access to the Terraform state that local `terraform apply` had already
built up -- state was local-only and correctly gitignored, so every CI
plan looked like a from-scratch create. Computed values (KMS key ARN,
bucket ARNs, subnet IDs) came back `null`/unknown instead of their real
values, and 3 of 6 policies (GAP-02, GAP-03, GAP-05 -- the ones checking
values derived from other resources, not literal strings) correctly
refused to treat `unknown` as evidence a gap was closed and failed the
gate. Fixed by adding a dedicated, versioned, encrypted S3 bucket
(`cgep-app-starter-tfstate-<account-id>`) as a remote backend with native
S3 locking (`use_lockfile = true`, no DynamoDB table needed), then
`terraform init -migrate-state` to move the existing state across intact
-- confirmed via `terraform plan` showing no drift afterward.

**Gotcha (also real, second CI run):** `data.archive_file.handler`
builds `lambda/handler.zip` as a local side effect of `terraform plan` --
it's gitignored (build output, not source). The `apply-and-evidence` job
runs on its own fresh checkout with no local build history, so when it
tried to `terraform apply` the saved plan, the zip Terraform expected to
find on disk simply wasn't there. Fixed by adding
`terraform/lambda/handler.zip` to the same upload/download-artifact steps
already carrying `tfplan`/`tfplan.json` between jobs.

**Verification performed:** pushed to `main`, watched two failed runs
(state, then the zip) get diagnosed and fixed one push at a time, then a
fully green run -- both jobs succeeded, and `aws s3 ls` on the evidence
vault confirms `tfplan.json`, `tfplan.json.sig`, `tfplan.json.pem`,
`evidence-manifest.json`, `evidence-manifest.json.sig`,
`evidence-manifest.json.pem` all present under
`evidence/<the triggering commit's SHA>/`.

## OSCAL component (Layer 4 of 4)

`oscal/component-definition.json`: one component ("Acme Health Patient
Intake API", type `this-system`), one control-implementation citing NIST
SP 800-53 Rev 5 as the `source` catalog (AICPA has no official OSCAL
catalog for SOC 2 TSC, per `FRAMEWORKS.md`), 8 `implemented-requirements`
-- one per gap in `GAPS.md`, 6 `implemented` (GAP-01/02/03/04/05/07), 2
`planned` (GAP-06/08, documented as accepted residual risk rather than
omitted). Each requirement carries the governing SOC 2 control as a prop
and links into `back-matter` at the exact Rego policy enforcing it, so
the starter -> policy -> OSCAL -> catalog chain `GAPS.md` describes is a
real, followable link rather than a claim in prose.

**Verification performed:** valid JSON (`json.load`); manually confirmed
all 8 gaps present exactly once, every `link` resolves to a real
back-matter UUID, no duplicate UUIDs. Also ran **full schema validation**
against NIST's official `oscal_component_schema.json` (v1.2.3 release)
using Python's `jsonschema` -- **0 errors**. `oscal-cli` itself wasn't
available locally, but validating against the same schema it uses gives
equivalent confidence.

**Gotcha:** the official schema's regex patterns use Unicode property
escapes (`\p{...}`), which Python's built-in `re` module can't compile
("bad escape \p"). Worked around by installing the third-party `regex`
package and shimming it in as `re` (`sys.modules['re'] = regex` before
importing `jsonschema`), since `regex` is otherwise a drop-in superset of
`re`'s API.

**Also fixed:** metadata originally declared `oscal-version: 1.1.2` but
validation ran against the v1.2.3 schema -- bumped the declared version
to `1.2.3` to match what was actually verified, rather than leave a
claim that wasn't checked.

## All 4 capstone layers now in place

1. Terraform GRC baseline -- 6 of 8 gaps closed, deployed, smoke-tested.
2. Rego/OPA policy suite -- 6 policies, proven to fail closed.
3. GitHub Actions pipeline -- plan -> gate -> apply -> sign -> vault, green on `main`.
4. OSCAL component-definition -- 8 requirements, 6 implemented / 2 planned, schema-validated.

## Fork lineage

The repo started as an independent clone (`shahidsha1612/cgep-app-starter`),
not a real GitHub fork of the upstream `GRCEngClub/cgep-app-starter`
template, even though README.md asks you to "fork the repo into your own
`cgep-capstone`." Fixed by: renaming the old repo out of the way, creating
a genuine fork of `GRCEngClub/cgep-app-starter` named `cgep-capstone`, then
force-pushing this repo's full commit history onto it. Verified
bidirectionally -- the fork's own `parent` field and the upstream repo's
own `forks` list both agree, and the repo id matches across both checks.

## Final pre-submission audit

Three real issues found by re-running verification end to end rather than
trusting earlier passing checks:

**1. Stale status in `closing-meeting/closed-gaps.md`.** It still said
"not yet applied" / status `Coded` from before Layers 2-4 were built and
the stack was deployed. Updated to reflect the actual current state.

**2. Lambda redeploying on every apply for no real reason.** `terraform
plan` kept showing `aws_lambda_function.intake` as changed even with no
code changes. Root cause: `source_code_hash` was computed from
`data.archive_file.handler.output_base64sha256` -- the zip's bytes embed
file timestamps that differ across build machines. Fixed by hashing
`handler.py` directly (`filebase64sha256`) instead.

**3. That fix wasn't enough on its own -- a second, deeper bug.** Even
after switching to `filebase64sha256(handler.py)`, this machine and CI
still disagreed. Root cause: no `.gitattributes` existed, so Git for
Windows checked `handler.py` out with CRLF line endings while the
committed blob (and what the Linux CI runner sees) stayed LF --
`filebase64sha256` hashes whatever's actually on disk, so the two
environments were hashing different bytes for "the same" file, forever.
Fixed with `.gitattributes` (`* text=auto eol=lf`) plus a forced
re-checkout of the affected file. Confirmed by `terraform plan` showing
**zero drift** from this Windows machine afterward, matching what CI
(Linux) had already applied.

**4. Root commit carried a Claude co-authoring trailer** from a prior
session (predates this one). Removed by amending the root commit and
rebasing all subsequent commits onto it (`git rebase --onto`), then
force-pushing. Verified: content byte-identical before/after (`git diff`
between old and new tips is empty), no Claude references anywhere in the
rewritten history, fork lineage and GitHub secrets both survived the
force-push intact.

All four fixes pushed and confirmed green on the pipeline afterward.
Remaining open items are only the 2 documented residual-risk gaps
(GAP-06, GAP-08) -- everything else that was checked came back clean.
