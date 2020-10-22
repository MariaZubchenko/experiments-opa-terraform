package terraform
import input.tfplan as tfplan
import input as tfplan

array_contains(arr, elem) {
  arr[_] = elem
}
denied_action = "0.0.0.0/0"
deny[reason] {
  r := tfplan.resource[_].aws_security_group[_].ssh_from_office[_].ingress[_].cidr_blocks
  array_contains(r, denied_action)
  reason := sprintf("Cidr block with %s from port 22 not allowed.", [r])
}
