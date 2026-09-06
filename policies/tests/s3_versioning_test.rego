package compliance.soc2.s3_versioning

import rego.v1

test_pass_when_enabled if {
	count(deny) == 0 with input as {"resource_changes": [{"type": "aws_s3_bucket_versioning", "change": {"after": {"versioning_configuration": [{"status": "Enabled"}]}}}]}
}

test_fail_when_suspended if {
	count(deny) == 1 with input as {"resource_changes": [{"type": "aws_s3_bucket_versioning", "change": {"after": {"versioning_configuration": [{"status": "Suspended"}]}}}]}
}

test_fail_when_resource_absent if {
	count(deny) == 1 with input as {"resource_changes": []}
}
