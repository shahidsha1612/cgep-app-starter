package compliance.soc2.lambda_iam_least_privilege

import rego.v1

good_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [
		{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": "arn:aws:dynamodb:::table/t"},
		{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::b/uploads/*"},
	],
})

bad_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}],
})

test_pass_when_scoped if {
	count(deny) == 0 with input as {"resource_changes": [{"address": "aws_iam_role_policy.lambda_inline", "type": "aws_iam_role_policy", "change": {"after": {"policy": good_policy}}}]}
}

test_fail_when_wildcard if {
	count(deny) == 1 with input as {"resource_changes": [{"address": "aws_iam_role_policy.lambda_inline", "type": "aws_iam_role_policy", "change": {"after": {"policy": bad_policy}}}]}
}
