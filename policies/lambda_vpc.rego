# METADATA
# title: GAP-05 -- intake Lambda must run inside the private VPC subnets
# custom:
#   framework: soc2
#   controls:
#     - "CC6.6"
#   severity: high
package compliance.soc2.lambda_vpc

import rego.v1

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_lambda_function"
	not vpc_configured(rc)
	msg := sprintf("GAP-05: %s has no vpc_config with subnet_ids -- the intake handler must run inside the private subnets, not the default shared network.", [rc.address])
}

vpc_configured(rc) if {
	count(rc.change.after.vpc_config[_].subnet_ids) > 0
}
