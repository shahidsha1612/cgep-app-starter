package compliance.soc2.s3_encryption

import rego.v1

good_input := {"resource_changes": [{
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}},
}]}

bad_input := {"resource_changes": [{
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"change": {"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]}},
}]}

test_pass_when_kms_configured if {
	count(deny) == 0 with input as good_input
}

test_fail_when_not_kms if {
	count(deny) == 1 with input as bad_input
}

test_fail_when_resource_absent if {
	count(deny) == 1 with input as {"resource_changes": []}
}
