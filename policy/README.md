# Policy suite (Layer 2)

Six Rego policies, one per closed gap, checked against a Terraform plan with
[Conftest](https://www.conftest.dev/). Each policy is tagged with the SOC 2
control it enforces (see each file's `METADATA` header).

| Policy | Gap | Control |
|---|---|---|
| `s3_encryption.rego` | GAP-01 | CC6.1 |
| `dynamodb_encryption.rego` | GAP-02 | CC6.1 |
| `s3_tls_only.rego` | GAP-03 | CC6.7 |
| `s3_versioning.rego` | GAP-04 | A1.2 |
| `lambda_vpc.rego` | GAP-05 | CC6.6 |
| `lambda_iam_least_privilege.rego` | GAP-07 | CC6.3 |

## Running it

From `terraform/`:

```bash
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
conftest test tfplan.json -p ../policy
```

A passing run means every closed gap is still present in the plan. If any gap
is reintroduced (e.g. someone deletes the KMS encryption block), the matching
policy fails the plan with a message naming the gap and what's missing.
