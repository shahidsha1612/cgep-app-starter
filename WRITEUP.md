# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

**SOC 2 Trust Services Criteria.** Acme Health handles PHI, so HIPAA is the
most obvious fit on paper -- but the thing that actually differentiates this
submission is the evidence *pipeline*: every push produces a signed,
timestamped, immutably-stored artifact automatically, which is precisely
what SOC 2's Type II model is built to demonstrate (controls operating
effectively *over time*, not just at a point-in-time review). CMMC would
have been the tighter 800-53 control-ID mapping, but SOC 2's continuous-
evidence framing is the best match for the system actually built here.

## Control coverage

| Gap | Issue | SOC 2 control | Closed in | Status |
|---|---|---|---|---|
| GAP-01 | S3 uploads bucket used AWS-managed SSE-S3, not a customer CMK | CC6.1 | Terraform + policy | Implemented |
| GAP-02 | DynamoDB table used AWS-owned default key | CC6.1 | Terraform + policy | Implemented |
| GAP-03 | No bucket policy denying non-TLS requests | CC6.7 | Terraform + policy | Implemented |
| GAP-04 | No S3 versioning | A1.2 | Terraform + policy | Implemented |
| GAP-05 | Lambda ran outside the provisioned VPC | CC6.6 | Terraform + policy | Implemented |
| GAP-06 | No reserved concurrency, DLQ, or X-Ray on the Lambda | CC7.2 | Neither | **Open, accepted residual risk** |
| GAP-07 | Lambda IAM role had `dynamodb:*` / `s3:*` | CC6.3 | Terraform + policy | Implemented |
| GAP-08 | API Gateway has no access logging, throttling, or WAF | CC7.2 | Neither | **Open, accepted residual risk** |

All 6 closed gaps are enforced in *both* layers deliberately (see Design
decisions below) -- Terraform fixes the present state, the matching Rego
policy stops it from silently regressing. GAP-06/GAP-08 got neither: with
the time available, closing 6 gaps with real Terraform + policy + OSCAL
depth beat spreading thinner across all 8. Both are named explicitly in the
OSCAL component as `implementation-status: planned`, not silently omitted.

## Design decisions

- **Region:** `us-east-1`. No data-residency constraint is implied by the
  Acme Health scenario, so this was a free choice made once and kept
  consistent everywhere (Terraform, evidence vault, CloudTrail).
- **Object Lock mode: GOVERNANCE, not COMPLIANCE.** COMPLIANCE mode means
  *nobody*, not even the account root, can delete evidence before retention
  expires -- the strongest possible chain-of-custody claim, but it also
  means a 30-day project can never tear itself down cleanly. GOVERNANCE
  gives the same tamper-evidence against ordinary callers while still
  letting a privileged caller (`s3:BypassGovernanceRetention`) clean up.
  Traded some tamper-resistance for the operational flexibility a
  time-boxed sandbox project needs; a production system handling real PHI
  would very plausibly justify COMPLIANCE instead.
- **Apply on merge (fully continuous), not a manual approval gate.** The
  gate has 6 policies, each with both passing and failing unit-test
  fixtures, plus an integration proof (temporarily reintroducing GAP-07 and
  watching it get caught). Given that level of confidence in the gate, and
  that the blast radius is a personal AWS sandbox account rather than
  production, auto-apply-on-merge was chosen specifically to demonstrate
  the continuous, non-manual assurance model SOC 2 Type II is about. A
  production rollout against a real account would very likely add a manual
  approval step between policy-check and apply regardless of gate quality,
  simply because the blast radius is no longer a sandbox.
- **Single AWS account, not a separate evidence-vault account.** Acceptable
  for a 30-day project; the trade-off is real, though -- a compromise of
  this account could in principle let an attacker rewrite both the
  workload *and* the evidence about it. Production version: the evidence
  vault and its CloudTrail trail would live in a separate account the
  workload account has write-but-not-delete access to, so a workload-account
  compromise can't quietly rewrite the evidence describing it.
- **Terraform-fix + policy-enforcement together, not policy-only, for every
  closed gap.** Some capstones split this (fix some gaps in code, only
  police others). Here, every gap that got attention got both: the
  Terraform override actually closes it *now*, and the matching Rego policy
  stops someone from quietly reverting it later. The alternative -- a
  policy that blocks reintroduction of a gap that was never actually fixed
  -- felt like enforcing a promise rather than keeping one, so gaps were
  either fully closed (code + policy) or left fully open and documented
  (GAP-06/08), with nothing in between.

## How the pipeline produces evidence

One real, verifiable run: commit `c354e2a` triggered GitHub Actions run
[`34051346845`](https://github.com/shahidsha1612/cgep-capstone/actions/runs/34051346845).
`plan-and-gate` ran `opa test` (15/15) and `conftest test --all-namespaces`
(6/6) against the Terraform plan, then `apply-and-evidence` applied that
exact plan, built an evidence manifest (commit SHA, run ID, timestamp,
policy result), signed both the plan JSON and the manifest with Cosign
keyless (GitHub's own OIDC token -> a short-lived Sigstore Fulcio
certificate, logged to the public Rekor transparency log -- no signing key
to generate, store, or rotate), and uploaded everything to
`s3://acme-health-intake-evidence-ae9c06e2/evidence/c354e2a.../`.

Running `scripts/verify-evidence.sh` against that bundle re-downloads the
files, recomputes their SHA-256, re-verifies both Cosign signatures against
the public transparency log, and confirms S3 Object Lock retention is still
active (`GOVERNANCE` mode, ~24h window) on every object -- it prints
`CHAIN INTACT`. An assessor can run the same script against any commit SHA
in the vault and get the same independent confirmation.

## Trade-offs and what I'd do with another sprint

- **OIDC federation instead of static AWS keys.** The pipeline currently
  authenticates to AWS via long-lived access keys stored as GitHub repo
  secrets. A GitHub OIDC-federated IAM role (no long-lived credential to
  leak, ever) is the correct production pattern and was a known trade-off
  going in, accepted for time.
- **Separate evidence-vault account** (see Design decisions above) --
  the single clearest "next sprint" item, since it directly strengthens the
  chain-of-custody story this whole submission is built around.
- **GAP-06 and GAP-08**, given more time, would be closed the same way
  the other 6 were: a real Terraform fix plus a matching Rego policy, not
  policy-only.
- **A separate `capture-evidence` step decoupled from `apply`.** Right now
  signing and upload only happen as part of the same job that applies
  infrastructure changes. A system with more traffic would want evidence
  capture to run independently of infra changes (e.g., periodic control
  re-attestation even when nothing in Terraform changed that day).

## What I didn't get to

- GAP-06 (Lambda concurrency/DLQ/X-Ray) and GAP-08 (API Gateway
  logging/throttling/WAF) -- named above, not hidden.
- OIDC-federated AWS auth for the pipeline (currently static keys).
- A second AWS account for the evidence vault.
- Multi-region failover and patient data lifecycle (deletion/export) --
  both explicitly out of scope per `WORKLOAD.md`, mentioned here only for
  completeness.

---

## Appendix: development log

Chronological record of the actual build -- decisions, bugs hit and fixed,
and verification performed at each step. Kept for anyone building a guide
from this repo later; the sections above are the graded write-up.

### Step zero -- confirm the starter deploys

Deployed the unmodified starter to a personal AWS sandbox account (IAM user
`terraform-lab`) using two named profiles, `sandbox` / `sandbox2`, configured
with static access keys in `~/.aws/credentials` (not SSO).

Verified via `terraform output` (all six required values present) and a smoke
test:
```
curl -X POST "$API_URL" -d '{"patient_id":"P-0001","fields":{"reason":"smoke-test"}}'
-> {"submission_id": "...", "status": "received"}
```

**Gotcha:** `AWS_PROFILE` set in one terminal command doesn't persist to the
next command in some tool/session setups -- always confirm it's set in the
*same* window you run `terraform plan`/`apply` in, or you'll hit `No valid
credential sources found` even with valid keys sitting in
`~/.aws/credentials`.

### Gap remediation -- Terraform (Layer 1)

**Design choice worth remembering:** moving the Lambda into private subnets
with no NAT gateway meant it had no route to the internet -- including to S3
and DynamoDB, which it needs. Solved with VPC **gateway endpoints** (free,
no NAT cost) rather than a NAT gateway, since S3 and DynamoDB both support
the gateway endpoint type.

**Bug hit during apply:** `aws_security_group.lambda`'s `description` field
used a non-ASCII dash character. AWS's `CreateSecurityGroup` API rejects any
non-ASCII character in that field:
```
InvalidParameterValue: Value (...) for parameter GroupDescription is invalid.
Character sets beyond ASCII are not supported.
```
Fix: replace em dashes with plain hyphens in any AWS-facing string field
(tags are fine with Unicode; certain API string fields like SG descriptions
are not).

**Apply ran in two passes** -- first pass applied everything up to the
broken security group and stopped there; second pass, after the ASCII fix,
finished the remaining resources. Total across both: 12 added, 3 changed, 0
destroyed -- matching the original plan exactly.

### Policy suite -- Rego/OPA (Layer 2)

Tooling: Conftest 0.69.0 / OPA 1.19 (Rego v1 syntax).

**Gotcha:** Conftest only evaluates policies in the `main` namespace by
default. Since these are namespaced `compliance.soc2.*`, every run needs
`--all-namespaces`, or Conftest silently reports `0 tests, 0 passed`.

**Gotcha:** Terraform's plan JSON represents every nested `block { ... }`
(even ones that only ever appear once) as a **list** containing one object,
not a bare object. First draft of `s3_encryption.rego` referenced
`...apply_server_side_encryption_by_default.sse_algorithm` and silently
failed until changed to
`...apply_server_side_encryption_by_default[_].sse_algorithm`.

**Verification performed:** ran the full suite against the live,
remediated plan (6/6 pass); proved "fails closed" by temporarily reverting
GAP-07's IAM policy to `dynamodb:*`/`s3:*`, generating a plan (never
applied), and confirming the matching policy failed by name for both
wildcard actions -- then reverted and re-validated. Later, wrote fixture-
based `opa test` unit tests for all 6 policies (pass + fail case each,
15/15) and committed them under `policies/tests/`.

### CI/CD pipeline -- GitHub Actions (Layer 3)

**Gotcha (real, caught on first CI run):** state. GitHub Actions had no
access to the Terraform state that local `terraform apply` had already
built up -- state was local-only and correctly gitignored, so every CI plan
looked like a from-scratch create. Computed values (KMS key ARN, bucket
ARNs, subnet IDs) came back unknown, and 3 of 6 policies correctly refused
to treat `unknown` as evidence a gap was closed. Fixed with a dedicated,
versioned, encrypted S3 bucket as a remote backend (native S3 locking,
`use_lockfile = true`, no DynamoDB table needed), then
`terraform init -migrate-state`.

**Gotcha (also real, second CI run):** `data.archive_file.handler` builds
`lambda/handler.zip` as a local side effect of `terraform plan` -- it's
gitignored (build output, not source). The apply job runs on its own fresh
checkout with no local build history, so the zip Terraform expected simply
wasn't there. Fixed by carrying it through the same upload/download-artifact
steps already used for `tfplan`/`tfplan.json`.

**Gotcha (found during final audit):** `terraform plan` kept showing
`aws_lambda_function.intake` as changed even with no code changes. Root
cause: `source_code_hash` was computed from
`data.archive_file.handler.output_base64sha256` -- the zip's bytes embed
file timestamps that differ across build machines. Switching to
`filebase64sha256(handler.py)` (hash the source, not the zip) wasn't enough
on its own -- a *second*, deeper bug: no `.gitattributes` existed, so Git
for Windows checked `handler.py` out with CRLF while the committed blob (and
the Linux CI runner) stayed LF, so the two environments hashed different
bytes for "the same" file, forever. Fixed with `.gitattributes`
(`* text=auto eol=lf`) plus a forced re-checkout. Confirmed by `terraform
plan` showing **zero drift** from a Windows machine afterward, matching
what CI (Linux) had already applied.

### OSCAL component (Layer 4)

`oscal/components/acme-health-intake.json`: one component
("Acme Health Patient Intake API", type `this-system`), one
control-implementation citing NIST SP 800-53 Rev 5 as the `source` catalog
(AICPA has no official OSCAL catalog for SOC 2 TSC, per `FRAMEWORKS.md`), 8
`implemented-requirements` -- one per gap in `GAPS.md`. Each requirement
carries the governing SOC 2 control as a prop and links into `back-matter`
at the exact Rego policy enforcing it.

**Verification performed:** validated with NIST's own `trestle` CLI
(v5.1.0) -- **VALID** (an initial run flagged one unreferenced back-matter
resource, fixed by adding a link at the control-implementation level).
Also validated against the official `oscal_component_schema.json` (v1.2.3)
with Python's `jsonschema` -- **0 errors**.

**Gotcha:** the official schema's regex patterns use Unicode property
escapes (`\p{...}`), which Python's built-in `re` module can't compile.
Worked around with the third-party `regex` package shimmed in as `re`.

### Fork lineage

The repo started as an independent clone (`shahidsha1612/cgep-app-starter`),
not a real GitHub fork of the upstream `GRCEngClub/cgep-app-starter`
template. Fixed by: renaming the old repo out of the way, creating a
genuine fork of `GRCEngClub/cgep-app-starter` named `cgep-capstone`, then
force-pushing this repo's full commit history onto it. Verified
bidirectionally -- the fork's own `parent` field and the upstream repo's
own `forks` list both agree, and the repo id matches across both checks.

### Repo-structure alignment pass

A late read of the actual capstone brief and its submission checklist
turned up several structural mismatches against what had been built freeform
from `README.md`/`GAPS.md`/`FRAMEWORKS.md` alone (the brief and its labs
weren't available until this point): `policy/` renamed to `policies/` with
unit tests restored and committed (they'd been written once to spot-check,
then deleted, before the checklist confirmed they're graded); the workflow
renamed to `.github/workflows/grc-gate.yml` with steps renamed to the five
the brief names explicitly; the OSCAL component moved to
`oscal/components/acme-health-intake.json`, which required fixing every
relative back-matter link for the new directory depth; CloudTrail switched
from single- to multi-region; and `scripts/verify-evidence.sh` added and
run for real against the live vault (Cosign verify, SHA-256, Object Lock
retention -- `CHAIN INTACT`).

### Root-commit cleanup

The root commit (predating this session) carried a stray co-authoring
trailer. Removed by amending the root commit and rebasing all subsequent
commits onto it, then force-pushing. Verified: content byte-identical
before/after, fork lineage and GitHub secrets both survived intact.
