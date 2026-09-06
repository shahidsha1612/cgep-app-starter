# Closing Meeting - Gap Remediation Record

**System:** Acme Health - Patient Intake API
**Framework:** SOC 2 Trust Services Criteria
**Diagram:** see `closed-gaps-stakeholder.html` (open in any browser)

## Deployment status

All fixes below are written in `terraform/main.tf` and pass `terraform validate`.
They have **not been applied** to the live AWS environment yet (session credentials
expired before `terraform plan`/`apply` could run). The deployed stack still reflects
the original 8-gap starter. Status column reflects **code**, not **production**, state.

## Gaps closed this pass (6 of 8 - 5 minimum required)

| Gap | Issue | Fix applied | SOC 2 control | Status |
|---|---|---|---|---|
| GAP-01 | S3 uploads bucket used AWS-managed SSE-S3, not a customer CMK | `aws_s3_bucket_server_side_encryption_configuration` under `aws_kms_key.phi` | CC6.1 | Coded |
| GAP-02 | DynamoDB table used AWS-owned default key | `server_side_encryption { kms_key_arn = aws_kms_key.phi.arn }` | CC6.1 | Coded |
| GAP-03 | No bucket policy denying non-TLS requests | `aws_s3_bucket_policy` denying requests where `aws:SecureTransport = false` | CC6.7 | Coded |
| GAP-04 | No versioning - PHI overwrites unrecoverable | `aws_s3_bucket_versioning`, status `Enabled` | A1.2 | Coded |
| GAP-05 | Lambda ran outside the provisioned VPC | Private route table + S3/DynamoDB gateway endpoints + locked-down security group + `vpc_config` on the Lambda | CC6.6 | Coded |
| GAP-07 | Lambda IAM role had `dynamodb:*` / `s3:*` | Scoped to `dynamodb:PutItem`, `s3:PutObject`, minimum KMS actions | CC6.3 | Coded |

## Gaps still open (out of scope this pass)

| Gap | Issue | SOC 2 control | Status |
|---|---|---|---|
| GAP-06 | No reserved concurrency, DLQ, or X-Ray on the Lambda | CC7.2 | Open |
| GAP-08 | API Gateway has no access logging, throttling, or WAF | CC7.2 | Open |

## Verification performed

- `terraform validate` - **passed**.
- `terraform plan` - not yet run (expired AWS credentials at time of writing).
- `terraform apply` - not yet run; live environment unchanged.

## Next steps

1. Re-authenticate to AWS (SSO/profile login).
2. Run `terraform plan` and review the change set.
3. Run `terraform apply` to bring the live stack in line with this record.
4. Decide whether GAP-06 / GAP-08 are addressed before final submission, or documented as accepted residual risk in the OSCAL component.
