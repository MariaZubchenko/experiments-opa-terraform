package terraform

import input.tfplan as tfplan

array_contains(arr, elem) {
  arr[_] = elem
}

# Part with sse in the process of testing. Not working yet, but I have ideas 
allowed_AES256_kms_master_key_id = ""
denied_kms_master_key_id = ""

s3_buckets[r] {
    r := input.resource_changes[_]
    r.type == "aws_s3_bucket"
}

#tags[t] {
#    t := input.resource_changes[_].change.after.tags
#    t.ContainsPCIData == "false"
#    t.ContainsPHIData == "false"
#    t.ContainsPIIData == "false"
#}

sse_encryption[e] {
    e := input.resource_changes[_].change.after.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default
}

deny_key[reason] {
    e := sse_encryption[_]
    array_contains(e.rule[_].apply_server_side_encryption_by_default[_].kms_master_key_id, denied_kms_master_key_id) 
    reason := sprintf(
        "Denied to use %s kms master key.",
        [e.kms_master_key_id]
    )
}

deny_sse[reason] {
    e := sse_encryption[_]
    not array_contains(allowed_AES256_kms_master_key_id, e.sse_algorithm) 
    reason := sprintf(
        "Denied to use %s sse algorithm.",
        [e.sse_algorithm]
    )
}

# Part with iam policies works as it should
iam_policy[p] {
    p := input.resource_changes[_]
    p.type == "aws_iam_role_policy"
}

denied_policy_kms_action_regex := ".*kms:*"

deny_policy_kms [reason] {
    p := iam_policy[_]
    regex.match(denied_policy_kms_action_regex, p.change.after.policy)
    reason := sprintf(
        "Policy %s not allowed.", 
        [p.change.after.name])
}

denied_policy_iam_action_regex := ".*iam:*"

deny_policy_iam [reason] {
    p := iam_policy[_]
    regex.match(denied_policy_iam_action_regex, p.change.after.policy)
    reason := sprintf(
        "Policy %s not allowed.", 
        [p.change.after.name])
}

# Part with cidr_blocks works as it should
cidr_blocks[c] {
    c := input.resource_changes[_]
    c.type == "aws_security_group"
}

denied_cidr := "10.5.0.0/16"
deny_cidr[reason] {
    c := cidr_blocks[_]
    array_contains(c.change.after.ingress[_].cidr_blocks, denied_cidr)
    reason := sprintf(
        "Cidr blocks %s not allowed in %v.", 
        [c.change.after.ingress[_].cidr_blocks, c.change.after.name])
}

