module "security" {
  source = "./modules/security"

  network_id            = yandex_vpc_network.default.id
  admin_cidrs           = var.admin_cidrs
  sws_dry_run           = var.sws_dry_run
  waf_paranoia_level    = var.waf_paranoia_level
  waf_anomaly_threshold = var.waf_anomaly_threshold
}
