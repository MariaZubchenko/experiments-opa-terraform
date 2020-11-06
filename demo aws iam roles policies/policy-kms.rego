package terraform

import input.tfplan as tfplan
import input as tfplan

array_contains(arr, elem) {
  arr[_] = elem
}

denied_action = "kms:*"

deny[reason] {
  r := tfplan.resource[_].aws_iam_role[_].test_role[_].assume_role_policy.Statement[_].Action
  array_contains(r, denied_action)
  reason := sprintf("Action kms %s not allowed.", [r])
}

allowed_name = [
  "test_role",
]
 
deny[reason] {
  r := tfplan.resource[_]
  role := r.aws_iam_role[_]
  testrole := role.test_role[_]
  name := testrole.name
  not array_contains(allowed_name, name)
  reason := sprintf("Name %s not allowed.", [name])
}
