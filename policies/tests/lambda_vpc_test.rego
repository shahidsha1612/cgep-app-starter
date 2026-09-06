package compliance.soc2.lambda_vpc

import rego.v1

test_pass_when_vpc_configured if {
	count(deny) == 0 with input as {"resource_changes": [{"address": "aws_lambda_function.intake", "type": "aws_lambda_function", "change": {"after": {"vpc_config": [{"subnet_ids": ["subnet-1", "subnet-2"]}]}}}]}
}

test_fail_when_no_vpc_config if {
	count(deny) == 1 with input as {"resource_changes": [{"address": "aws_lambda_function.intake", "type": "aws_lambda_function", "change": {"after": {"vpc_config": []}}}]}
}
