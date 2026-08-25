locals {
  owasp_crs_name    = "OWASP Core Ruleset"
  owasp_crs_version = "4.0.0"
  # The WAF create API expects the internal rule-set enum rather than the
  # display ID returned by yandex_sws_waf_rule_set_descriptor.
  owasp_crs_id = "OWASP_CRS_4_0_0"
}

data "yandex_sws_waf_rule_set_descriptor" "owasp" {
  name    = local.owasp_crs_name
  version = local.owasp_crs_version
}

resource "yandex_logging_group" "sws" {
  name             = "sws-test-sws-logs"
  description      = "Smart Web Security request and rule logs"
  retention_period = "72h"
}

resource "yandex_sws_waf_profile" "test" {
  name        = "sws-test-waf"
  description = "OWASP CRS profile for the SWS test application"

  rule_set {
    action     = "DENY"
    is_enabled = true
    priority   = 1

    core_rule_set {
      inbound_anomaly_score = var.waf_anomaly_threshold
      paranoia_level        = var.waf_paranoia_level

      rule_set {
        id      = local.owasp_crs_id
        name    = local.owasp_crs_name
        version = local.owasp_crs_version
        type    = "CORE"
      }
    }
  }

  dynamic "rule" {
    for_each = [
      for rule in data.yandex_sws_waf_rule_set_descriptor.owasp.rules : rule
      if rule.paranoia_level <= var.waf_paranoia_level
    ]

    content {
      rule_id     = rule.value.id
      is_enabled  = true
      is_blocking = false
    }
  }
}

resource "yandex_sws_security_profile" "test" {
  name           = "sws-test-security-profile"
  description    = "Smart Protection and OWASP WAF for the SWS test application"
  default_action = "ALLOW"

  log_options {
    enable                   = true
    log_group_id             = yandex_logging_group.sws.id
    enabled_modules          = ["SMART_PROTECTION", "WAF"]
    enabled_actions          = ["ALLOW", "DENY", "CAPTCHA"]
    discard_allow_percentage = 0
    outputs                  = ["CLOUD_LOGGING"]
  }

  security_rule {
    name        = "waf"
    description = "Inspect all requests with OWASP CRS"
    priority    = 888800
    dry_run     = var.sws_dry_run

    waf {
      mode           = "FULL"
      waf_profile_id = yandex_sws_waf_profile.test.id
    }
  }

  security_rule {
    name        = "smart-protection"
    description = "Analyze all requests for automated and suspicious traffic"
    priority    = 999900
    dry_run     = var.sws_dry_run

    smart_protection {
      mode = "FULL"
    }
  }
}
