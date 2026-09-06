# Closing Meeting - Gap Remediation Record

**System:** Acme Health - Patient Intake API
**Framework:** SOC 2 Trust Services Criteria
**Diagram:** see `closed-gaps-stakeholder.html` (open in any browser)

## Deployment status

All fixes below are applied to the live AWS environment and verified working --
a post-remediation smoke test against `/intake` returned `HTTP 200` with a real
`submission_id` after the Lambda moved inside the VPC. The full pipeline (Layers
2-4: Rego policy suite, GitHub Actions, OSCAL component) is also built and green.

## Gaps closed this pass (6 of 8 - 5 minimum required)

| Gap | Issue | Fix applied | SOC 2 control | Status |
|---|---|---|---|---|
| GAP-01 | S3 uploads bucket used AWS-managed SSE-S3, not a customer CMK | `aws_s3_bucket_server_side_encryption_configuration` under `aws_kms_key.phi` | CC6.1 | Deployed |
| GAP-02 | DynamoDB table used AWS-owned default key | `server_side_encryption { kms_key_arn = aws_kms_key.phi.arn }` | CC6.1 | Deployed |
| GAP-03 | No bucket policy denying non-TLS requests | `aws_s3_bucket_policy` denying requests where `aws:SecureTransport = false` | CC6.7 | Deployed |
| GAP-04 | No versioning - PHI overwrites unrecoverable | `aws_s3_bucket_versioning`, status `Enabled` | A1.2 | Deployed |
| GAP-05 | Lambda ran outside the provisioned VPC | Private route table + S3/DynamoDB gateway endpoints + locked-down security group + `vpc_config` on the Lambda | CC6.6 | Deployed |
| GAP-07 | Lambda IAM role had `dynamodb:*` / `s3:*` | Scoped to `dynamodb:PutItem`, `s3:PutObject`, minimum KMS actions | CC6.3 | Deployed |

## Gaps still open (accepted residual risk, documented in OSCAL)

| Gap | Issue | SOC 2 control | Status |
|---|---|---|---|
| GAP-06 | No reserved concurrency, DLQ, or X-Ray on the Lambda | CC7.2 | Open |
| GAP-08 | API Gateway has no access logging, throttling, or WAF | CC7.2 | Open |

## Verification performed

- `terraform validate` / `terraform plan` / `terraform apply` -- all passed, live stack matches config with zero drift.
- Post-remediation smoke test against `/intake` -- `HTTP 200`.
- `conftest` policy suite (6 policies) -- 6/6 pass against the deployed plan; proven to fail closed by temporarily reintroducing GAP-07.
- GitHub Actions pipeline -- green on `main`, signed evidence confirmed present in the S3 evidence vault.
- OSCAL `component-definition.json` -- validated against NIST's official schema, 0 errors.

See `WRITEUP.md` for the full technical log, including gotchas hit and fixed along the way.
