# METADATA
# title: GAP-07 -- Lambda role must not hold wildcard dynamodb:*/s3:* actions
# custom:
#   framework: soc2
#   controls:
#     - "CC6.3"
#   severity: high
package compliance.soc2.lambda_iam_least_privilege

import rego.v1

wildcard_actions := {"dynamodb:*", "s3:*"}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role_policy"
	policy := json.unmarshal(rc.change.after.policy)
	some stmt in policy.Statement
	action := as_set(stmt.Action)
	some a in action
	a in wildcard_actions
	msg := sprintf("GAP-07: %s grants wildcard action %q -- scope the Lambda role to the specific actions it performs.", [rc.address, a])
}

as_set(x) := {x} if is_string(x)

as_set(x) := {a | some a in x} if is_array(x)
