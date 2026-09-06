# METADATA
# title: GAP-02 -- DynamoDB submissions table must use a customer CMK
# custom:
#   framework: soc2
#   controls:
#     - "CC6.1"
#   severity: high
package compliance.soc2.dynamodb_encryption

import rego.v1

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_dynamodb_table"
	not cmk_encryption_enabled(rc)
	msg := sprintf("GAP-02: %s has no server_side_encryption block backed by a customer-managed KMS key.", [rc.address])
}

cmk_encryption_enabled(rc) if {
	sse := rc.change.after.server_side_encryption[_]
	sse.enabled == true
	sse.kms_key_arn != null
	sse.kms_key_arn != ""
}
