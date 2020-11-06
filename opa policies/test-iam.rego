package terraform

import input.tfplan as tfplan
import data.base 

__rego__metadoc__ := {
  "id": "FG_R00092",
  "title": "IAM policies should not have full \"*:*\" administrative privileges",
  "description": "IAM policies should not have full \"*:*\" administrative privileges. IAM policies should start with a minimum set of permissions and include more as needed rather than starting with full administrative privileges. Providing full administrative privileges when unnecessary exposes resources to potentially unwanted actions.",
  "custom": {
    "controls": {
      "CIS": [
        "CIS_1-22"
      ]
    },
    "severity": "High"
  }
}

resource_type = "MULTIPLE"

policies[name] = p {
  iam_policies := base.resources("aws_iam_policy")
  p = iam_policies[name]
} {
  group_policies = base.resources("aws_iam_group_policy")
  p = group_policies[name]
} {
  role_policies = base.resources("aws_iam_role_policy")
  p = role_policies[name]
} {
  user_policies = base.resources("aws_iam_user_policy")
  p = user_policies[name]
}

wildcard_policies[name] = p {
  p = policies[name]
  is_wildcard_policy(p)
}

is_wildcard_policy(p) {
  json.unmarshal(p.policy, doc)
  statements = as_array(doc.Statement)
  statement = statements[_]

  statement.Effect == "Allow"

  resources = as_array(statement.Resource)
  resource = resources[_].after.change.policy
  resource == "*"

  actions = as_array(statement.Action)
  action = actions[_]
  action == "*"
}

policy[p] {
  single_policy = wildcard_policies[name]
  p = base.deny_resource(single_policy)
} {
  single_policy = policies[name]
  not wildcard_policies[name]
  p = base.allow_resource(single_policy)
}

# Utility: turns anything into an array, if it's not an array already.
as_array(x) = [x] {not is_array(x)} else = x {true}
