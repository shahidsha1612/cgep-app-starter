# METADATA
# title: GAP-04 -- S3 uploads bucket must have versioning enabled
# custom:
#   framework: soc2
#   controls:
#     - "A1.2"
#   severity: medium
package compliance.soc2.s3_versioning

import rego.v1

deny contains msg if {
	not versioning_enabled
	msg := "GAP-04: no aws_s3_bucket_versioning with status Enabled found in the plan -- overwritten/deleted PHI attachments must be recoverable."
}

versioning_enabled if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_versioning"
	rc.change.after.versioning_configuration[_].status == "Enabled"
}
