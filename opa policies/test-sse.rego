package terraform

import input.tfplan as tfplan
import data.base

resource_type = "MULTIPLE"

taggable_resource_types = {
  "aws_cloudfront_distribution",
  "aws_cloudwatch_event_rule",
  "aws_cloudwatch_log_group",
  "aws_cloudwatch_metric_alarm",
  "aws_cognito_user_pool",
  "aws_config_config_rule",
  "aws_customer_gateway",
  "aws_db_event_subscription",
  "aws_db_instance",
  "aws_db_option_group",
  "aws_db_parameter_group",
  "aws_db_subnet_group",
  "aws_dynamodb_table",
  "aws_ebs_volume",
  "aws_eip",
  "aws_elasticache_cluster",
  "aws_elb",
  "aws_instance",
  "aws_internet_gateway",
  "aws_kms_key",
  "aws_lambda_function",
  "aws_lb",
  "aws_lb_target_group",
  "aws_network_acl",
  "aws_network_interface",
  "aws_redshift_cluster",
  "aws_redshift_parameter_group",
  "aws_redshift_subnet_group",
  "aws_route53_health_check",
  "aws_route53_zone",
  "aws_route_table",
  "aws_s3_bucket",
  "aws_security_group",
  "aws_sfn_state_machine",
  "aws_subnet",
  "aws_vpc",
  "aws_vpc",
  "aws_vpc_dhcp_options",
  "aws_vpn_connection",
  "aws_vpn_gateway",
}

taggable_resources[id] = resource {
  some resource_type
  taggable_resource_types[resource_type]
  resources = input.resource_changes[_]
  resource = resources.type[id]
}

is_tagged(resource) {
  resource[_].change.after.tags[_] = _
}

is_improperly_tagged(resource) = msg {
  resource[_].change.after.tags[key] = val
  val == "confidential"
  msg = sprintf("Tag %s exist", [key])
} else = "No tags found" {
  not is_tagged(resource)
}

policy[r] {
   resource = taggable_resources[_]
   msg = is_improperly_tagged(resource)
   r = base.deny_resource_with_message(resource, msg)
} {
   resource = taggable_resources[_]
   not is_improperly_tagged(resource)
   r = base.allow_resource(resource)
}