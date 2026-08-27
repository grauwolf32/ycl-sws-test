module "security" {
  source = "./modules/security"

  network_id                     = yandex_vpc_network.default.id
  admin_cidrs                    = var.admin_cidrs
  sws_dry_run                    = var.sws_dry_run
  waf_active_ruleset             = var.waf_active_ruleset
  yandex_ruleset_direct_blocking = var.yandex_ruleset_direct_blocking
  yandex_ruleset_rule_groups     = var.yandex_ruleset_rule_groups
  api_path_prefix                = var.sws_api_path_prefix
  grpc_backend_port              = var.grpc_backend_port
  waf_body_size_limit_kb         = var.waf_body_size_limit_kb
  waf_body_size_limit_action     = var.waf_body_size_limit_action
  waf_paranoia_level             = var.waf_paranoia_level
  waf_disabled_rule_ids          = var.waf_disabled_rule_ids
  waf_grpc_excluded_rule_ids     = var.waf_grpc_excluded_rule_ids
  waf_anomaly_threshold          = var.waf_anomaly_threshold
}
