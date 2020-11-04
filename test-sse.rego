package terraform

import input.tfplan as tfplan

AES256_sse_encryption := "AES256"

sse_encryption[e] {
    e := input.resource_changes[_].change.after.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_]
}

s3bucket [s] {
    s := input.resource_changes[_].change.after.bucket
}
required_algorithm = ["aws:kms", "AES256"]


array_contains(arr, elem) {
  arr[_] = elem
}

# algo {
#     algorithm := e.sse_algorithm
# }
tags(resource) = algo {
    tags := input.resource_changes[_].change.after.tags.DataClassification
    "confidential" == DataClassification
} else = algo {
    algorithm := e.sse_algorithm
} else = empty {
    empty := {}
}

deny[reason] {
    resource := input.resource_changes[_]
    tags == tags(resource)
    required_algorithm := algorithm[_] 
    s == s.s3bucket 
    not array_contains(e.sse_algorithm, required_algorithm)
    reason := sprintf(
        "%s: missing required tag %q",
        [s.s3bucket, required_algorithm]
    )
}