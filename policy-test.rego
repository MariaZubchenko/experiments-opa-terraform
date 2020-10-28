package terraform

import input.tfplan as tfplan

array_contains(arr, elem) {
  arr[_] = elem
}

# Part wiht sse in the process of testing. Not working yet, but I have ideas 
allowed_AES256_kms_master_key_id = ""
denied_kms_master_key_id = "1"

s3_buckets[r] {
    r := input.resource_changes[_]
    r.type == "aws_s3_bucket"
}

tags[t] {
    t := input.resource_changes[_].change.after.tags
    t.ContainsPCIData == "false"
    t.ContainsPHIData == "false"
    t.ContainsPIIData == "false"
}

sse_encryption[e] {
    e := input.resource_changes[_].change.after.server_side_encryption_configuration[_]
}

deny_sse[reason] {
    e := sse_encryption[_]
    not tags[_],
    array_contains(e.rule[_].apply_server_side_encryption_by_default[_].kms_master_key_id, denied_kms_master_key_id) 
    reason := sprintf(
        "Denied to use %s kms master key.",
        [e.rule[_].apply_server_side_encryption_by_default[_].kms_master_key_id]
    )
}

# It doesn't work, I don't know how to get the Action out of the policy. I will think about it.
iam_policy[p] {
    p := input.resource_changes[_]
    p.type == "aws_iam_role_policy"
}

denied_action := "s3:*"
deny [reason] {
    p := iam_policy[_].change.after.policy
    p.policy == ""
    array_contains(p.change.after.policy, denied_action)
    reason := sprintf(
        "Action %s not allowed.", 
        [p.change.after.policy])
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

