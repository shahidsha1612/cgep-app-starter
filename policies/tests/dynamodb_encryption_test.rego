package compliance.soc2.dynamodb_encryption

import rego.v1

good_input := {"resource_changes": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"change": {"after": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:123:key/abc"}]}},
}]}

bad_input := {"resource_changes": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"change": {"after": {}},
}]}

test_pass_when_cmk_configured if {
	count(deny) == 0 with input as good_input
}

test_fail_when_no_encryption_block if {
	count(deny) == 1 with input as bad_input
}
