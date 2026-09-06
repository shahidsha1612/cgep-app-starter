package compliance.soc2.s3_tls_only

import rego.v1

good_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "DenyInsecureTransport",
		"Effect": "Deny",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}],
})

bad_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}],
})

test_pass_when_tls_deny_present if {
	count(deny) == 0 with input as {"resource_changes": [{"type": "aws_s3_bucket_policy", "change": {"after": {"policy": good_policy}}}]}
}

test_fail_when_no_tls_deny if {
	count(deny) == 1 with input as {"resource_changes": [{"type": "aws_s3_bucket_policy", "change": {"after": {"policy": bad_policy}}}]}
}

test_fail_when_resource_absent if {
	count(deny) == 1 with input as {"resource_changes": []}
}
