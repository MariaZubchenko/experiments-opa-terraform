package terraform

import input.tfplan as tfplan

array_contains(arr, elem) {
  arr[_] = elem
}

allowed_acls = ["private"]
allowed_sse_algorithms = ["aws:kms", "AES256"]

s3_buckets[r] {
    r := input.resource_changes[_]
    r.type == "aws_s3_bucket"
}

iam_policy[p] {
    p := input.resource_changes[_]
    p.type == "aws_iam_role_policy"
}

# Rule to restrict S3 bucket ACLs
deny_acl[reason] {
    r := s3_buckets[_]
    not array_contains(allowed_acls, r.change.after.acl)
    reason := sprintf(
        "%s: ACL %q is not allowed",
        [r.address, r.change.after.acl]
    )
}

#Rule to require server-side encryption
deny_sse[reason] {
    r := s3_buckets[_]
    count(r.change.after.server_side_encryption_configuration) == 0
    reason := sprintf(
        "%s: requires server-side encryption with expected sse_algorithm to be one of %v",
        [r.address, allowed_sse_algorithms]
    )
}

#Rule to enforce specific SSE algorithms
deny[reason] {
    r := s3_buckets[_]
    sse_configuration := r.change.after.server_side_encryption_configuration[_]
    apply_sse_by_default := sse_configuration.rule[_].apply_server_side_encryption_by_default[_]
    not array_contains(allowed_sse_algorithms, apply_sse_by_default.sse_algorithm)
    reason := sprintf(
        "%s: expected sse_algorithm to be one of %v",
        [r.address, allowed_sse_algorithms] 
        )
}

# Rule to deny opened ports
denied_cidr := "10.5.0.0/16"
deny_cidr[reason] {
  res := input.planned_values.root_module.child_modules[_].resources[_].values.ingress[_].cidr_blocks #.values.ingress[_].cidr_blocks[_]
  array_contains(res, denied_cidr)
  reason := sprintf("Cidr block %v not allowed.", [res])
}

denied_action = "s3:*"
# denied_action2 = "iam:*"
# denied_resource = "arn:aws:kms:*"

deny_kms[reason] {
  #re := input.configuration.root_module.module_calls.cloudtrail.module.resources[_].expressions.statement[_].actions.constant_value
  p := iam_policy[_]
  array_contains(p.change.after.policy.Action, denied_action)
  reason := sprintf("Action %s not allowed.", [p])
}

# deny[reason] {
#   r := tfplan.get_resources_by_type
#   array_contains(r, denied_action2)
#   reason := sprintf("Action %s not allowed.", [r])
# }
# deny[reason] {
#   r := tfplan.get_resources_by_type
#   array_contains(r, denied_resource)
#   reason := sprintf("Resource %s not allowed with this action.", [r])
# }
