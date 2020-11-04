package terraform

array_contains(arr, elem) {
  arr[_] = elem
}

# as_array(x) = [x] {not is_array(x)} else = x {true}



# policies[name] = p {
#   iam_policies = input.resource_changes["aws_iam_policy"]
#   p = iam_policies[name]
# } {
#   group_policies = input.resource_changes["aws_iam_group_policy"]
#   p = group_policies[name]
# } {
#   role_policies = input.resource_changes["aws_iam_role_policy"]
#   p = role_policies[name]
# } {
#   user_policies = input.resource_changes["aws_iam_user_policy"]
#   p = user_policies[name]
# }

# wildcard_policies[name] = p {
#   p = iam_policy[name]
#   is_wildcard_policy(p)
# }

# is_wildcard_policy(p) {
#   json.unmarshal(p.iam_policy)
#   #json.unmarshal(p.iam_policy, doc)
#   statements = as_array(p.iam_policy.Statement)
#   #statements = as_array(doc.Statement)
#   statement = statements[_]

# #   statement.Effect == "Allow"

# #   resources = as_array(statement.Resource)
# #   resource = resources[_]
# #   resource == "*"

#   actions = as_array(statement.Action)
#   action = actions[_]
#   action == "kms:*"
# }

# policy[k] {
#     k := p.
# } 
iam_policy[p] {
    p := json.unmarshal(input.resource_changes[_].change.after.policy)
    #p.type == "aws_iam_role_policy"
}

denied_policy_action := "test"

deny_policy [reason] {
    p := iam_policy[_]
    #single_policy = wildcard_policies[name]
    array_contains(p.iam_policy, denied_policy_action)
    reason := sprintf(
        "policy %s not allowed", 
        [p.change.after.name])
}
