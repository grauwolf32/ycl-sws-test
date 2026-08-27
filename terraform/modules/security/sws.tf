locals {
  owasp_crs_name    = "OWASP Core Ruleset"
  owasp_crs_version = "4.0.0"
  # The WAF create API expects the internal rule-set enum rather than the
  # display ID returned by yandex_sws_waf_rule_set_descriptor.
  owasp_crs_id = "OWASP_CRS_4_0_0"

  yandex_ruleset_name    = "Yandex Ruleset"
  yandex_ruleset_version = "0.1.1"
  yandex_ruleset_id      = "YARS_0_1_1"
  yandex_ruleset_required_group_ids = toset([
    "yars-v0.1.1-attack-cve",
    "yars-v0.1.1-attack-lfi",
    "yars-v0.1.1-attack-rce",
    "yars-v0.1.1-attack-rfi",
    "yars-v0.1.1-attack-sqli",
    "yars-v0.1.1-attack-tool",
    "yars-v0.1.1-attack-xss",
  ])
}

data "yandex_sws_waf_rule_set_descriptor" "owasp" {
  name    = local.owasp_crs_name
  version = local.owasp_crs_version
}

data "yandex_sws_waf_rule_set_descriptor" "yandex" {
  name    = local.yandex_ruleset_name
  version = local.yandex_ruleset_version
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
      is_enabled  = !contains(var.waf_disabled_rule_ids, rule.value.id)
      is_blocking = false
    }
  }

  dynamic "exclusion_rule" {
    for_each = length(var.waf_grpc_excluded_rule_ids) == 0 ? [] : [true]

    content {
      name         = "grpc-protocol-false-positives"
      description  = "Ignore confirmed OWASP CRS false positives caused by HTTP/2 and protobuf framing"
      log_excluded = true

      exclude_rules {
        rule_ids = sort(tolist(var.waf_grpc_excluded_rule_ids))
      }

      condition {
        headers {
          name = "content-type"

          value {
            prefix_match = "application/grpc"
          }
        }
      }
    }
  }
}

resource "yandex_sws_waf_profile" "yandex" {
  name        = "sws-test-waf-yandex"
  description = "Yandex Ruleset profile for controlled comparison with OWASP CRS"

  rule_set {
    action     = "DENY"
    is_enabled = true
    priority   = 1

    ya_rule_set {
      rule_set {
        id      = local.yandex_ruleset_id
        name    = local.yandex_ruleset_name
        version = local.yandex_ruleset_version
        type    = "YA"
      }

      dynamic "rule_group" {
        for_each = var.yandex_ruleset_rule_groups

        content {
          id                    = rule_group.key
          action                = rule_group.value.action
          inbound_anomaly_score = rule_group.value.inbound_anomaly_threshold
          is_enabled            = rule_group.value.is_enabled
        }
      }
    }
  }

  dynamic "rule" {
    for_each = data.yandex_sws_waf_rule_set_descriptor.yandex.rules

    content {
      rule_id     = rule.value.id
      is_enabled  = true
      is_blocking = var.yandex_ruleset_direct_blocking
    }
  }

  lifecycle {
    precondition {
      condition = var.yandex_ruleset_direct_blocking || (
        length(setsubtract(local.yandex_ruleset_required_group_ids, toset(keys(var.yandex_ruleset_rule_groups)))) == 0 &&
        length(setsubtract(toset(keys(var.yandex_ruleset_rule_groups)), local.yandex_ruleset_required_group_ids)) == 0
      )
      error_message = "Yandex Ruleset needs explicit settings for all seven 0.1.1 groups unless direct blocking is enabled for discovery."
    }
  }
}

locals {
  active_waf_profile_id = var.waf_active_ruleset == "YANDEX_RULESET" ? yandex_sws_waf_profile.yandex.id : yandex_sws_waf_profile.test.id
}

resource "yandex_sws_security_profile" "test" {
  name           = "sws-test-security-profile"
  description    = "Managed WAF with API-safe and browser protection modes"
  default_action = "ALLOW"

  analyze_request_body {
    size_limit        = var.waf_body_size_limit_kb
    size_limit_action = var.waf_body_size_limit_action
  }

  log_options {
    enable                   = true
    log_group_id             = yandex_logging_group.sws.id
    enabled_modules          = ["SMART_PROTECTION", "WAF"]
    enabled_actions          = ["ALLOW", "DENY", "CAPTCHA"]
    discard_allow_percentage = 0
    outputs                  = ["CLOUD_LOGGING"]
  }

  security_rule {
    name        = "waf-health"
    description = "Inspect liveness checks in API mode without CAPTCHA redirects"
    priority    = 888400
    dry_run     = var.sws_dry_run

    waf {
      mode           = "API"
      waf_profile_id = local.active_waf_profile_id

      condition {
        request_uri {
          path {
            prefix_match = "/healthz"
          }
        }
      }
    }
  }

  security_rule {
    name        = "waf-readiness"
    description = "Inspect readiness checks in API mode without CAPTCHA redirects"
    priority    = 888500
    dry_run     = var.sws_dry_run

    waf {
      mode           = "API"
      waf_profile_id = local.active_waf_profile_id

      condition {
        request_uri {
          path {
            prefix_match = "/readyz"
          }
        }
      }
    }
  }

  security_rule {
    name        = "waf-grpc"
    description = "Inspect gRPC requests in API mode without CAPTCHA redirects"
    priority    = 888600
    dry_run     = var.sws_dry_run

    waf {
      mode           = "API"
      waf_profile_id = local.active_waf_profile_id

      condition {
        headers {
          name = "content-type"

          value {
            prefix_match = "application/grpc"
          }
        }
      }
    }
  }

  security_rule {
    name        = "waf-api"
    description = "Inspect API requests without redirecting clients to CAPTCHA"
    priority    = 888700
    dry_run     = var.sws_dry_run

    waf {
      mode           = "API"
      waf_profile_id = local.active_waf_profile_id

      condition {
        request_uri {
          path {
            prefix_match = var.api_path_prefix
          }
        }
      }
    }
  }

  security_rule {
    name        = "waf-browser"
    description = "Inspect all other requests with managed WAF and full browser protection"
    priority    = 888800
    dry_run     = var.sws_dry_run

    waf {
      mode           = "FULL"
      waf_profile_id = local.active_waf_profile_id
    }
  }
}
