# METADATA
# title: GAP-03 -- S3 uploads bucket must deny non-TLS requests
# custom:
#   framework: soc2
#   controls:
#     - "CC6.7"
#   severity: medium
package compliance.soc2.s3_tls_only

import rego.v1

deny contains msg if {
	not tls_deny_policy_present
	msg := "GAP-03: no aws_s3_bucket_policy denying aws:SecureTransport=false found in the plan -- the uploads bucket must refuse non-HTTPS requests."
}

tls_deny_policy_present if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_policy"
	policy := json.unmarshal(rc.change.after.policy)
	some stmt in policy.Statement
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
}
