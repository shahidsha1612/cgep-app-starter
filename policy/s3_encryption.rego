# METADATA
# title: GAP-01 -- S3 uploads bucket must use SSE-KMS with a customer CMK
# custom:
#   framework: soc2
#   controls:
#     - "CC6.1"
#   severity: high
package compliance.soc2.s3_encryption

import rego.v1

deny contains msg if {
	not sse_kms_configured
	msg := "GAP-01: no aws_s3_bucket_server_side_encryption_configuration using aws:kms found in the plan -- the uploads bucket must encrypt under a customer-managed KMS key, not the AWS-managed default."
}

sse_kms_configured if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	rc.change.after.rule[_].apply_server_side_encryption_by_default[_].sse_algorithm == "aws:kms"
}
