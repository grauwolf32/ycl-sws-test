variable "network_id" {
  description = "VPC network that owns the security groups."
  type        = string
}

variable "admin_cidrs" {
  description = "Public IPv4 /32 CIDRs allowed to connect to backend VMs over SSH."
  type        = set(string)
}

variable "sws_dry_run" {
  description = "Run SWS WAF rules in logging-only mode without affecting traffic."
  type        = bool
}

variable "waf_active_ruleset" {
  description = "Managed WAF rule set attached to SWS: OWASP_CRS or YANDEX_RULESET."
  type        = string

  validation {
    condition     = contains(["OWASP_CRS", "YANDEX_RULESET"], var.waf_active_ruleset)
    error_message = "waf_active_ruleset must be OWASP_CRS or YANDEX_RULESET."
  }
}

variable "yandex_ruleset_direct_blocking" {
  description = "Make every enabled Yandex Ruleset signature blocking during controlled discovery."
  type        = bool
}

variable "yandex_ruleset_rule_groups" {
  description = "Yandex Ruleset group settings keyed by opaque group ID."
  type = map(object({
    action                    = optional(string, "DENY")
    inbound_anomaly_threshold = optional(number, 7)
    is_enabled                = optional(bool, true)
  }))

  validation {
    condition = alltrue([
      for group in values(var.yandex_ruleset_rule_groups) :
      contains(["DENY", "LOG", "IGNORE"], group.action) &&
      group.inbound_anomaly_threshold >= 1 && group.inbound_anomaly_threshold <= 10000 &&
      floor(group.inbound_anomaly_threshold) == group.inbound_anomaly_threshold
    ])
    error_message = "Each Yandex Ruleset group needs action DENY, LOG, or IGNORE and an integer threshold from 1 to 10000."
  }
}

variable "api_path_prefix" {
  description = "Request path prefix protected in API mode without CAPTCHA redirects."
  type        = string

  validation {
    condition     = startswith(var.api_path_prefix, "/") && !strcontains(var.api_path_prefix, "?") && !strcontains(var.api_path_prefix, "#")
    error_message = "api_path_prefix must be an absolute request path without a query string or fragment."
  }
}

variable "grpc_backend_port" {
  description = "TCP port exposed by backend VMs for native gRPC traffic."
  type        = number

  validation {
    condition     = var.grpc_backend_port >= 1 && var.grpc_backend_port <= 65535 && floor(var.grpc_backend_port) == var.grpc_backend_port
    error_message = "grpc_backend_port must be an integer from 1 to 65535."
  }
}

variable "waf_body_size_limit_kb" {
  description = "Maximum request body size inspected by SWS, in KiB."
  type        = number

  validation {
    condition     = var.waf_body_size_limit_kb >= 1 && var.waf_body_size_limit_kb <= 8 && floor(var.waf_body_size_limit_kb) == var.waf_body_size_limit_kb
    error_message = "waf_body_size_limit_kb must be an integer from 1 to 8."
  }
}

variable "waf_body_size_limit_action" {
  description = "SWS action when a request body exceeds the inspection limit: IGNORE or DENY."
  type        = string

  validation {
    condition     = contains(["IGNORE", "DENY"], var.waf_body_size_limit_action)
    error_message = "waf_body_size_limit_action must be IGNORE or DENY."
  }
}

variable "waf_paranoia_level" {
  description = "Maximum OWASP CRS paranoia level whose rules are enabled."
  type        = number

  validation {
    condition     = var.waf_paranoia_level >= 1 && var.waf_paranoia_level <= 4 && floor(var.waf_paranoia_level) == var.waf_paranoia_level
    error_message = "waf_paranoia_level must be an integer from 1 to 4."
  }
}

variable "waf_disabled_rule_ids" {
  description = "OWASP CRS rule IDs disabled globally after confirmed protocol false positives."
  type        = set(string)
}

variable "waf_grpc_excluded_rule_ids" {
  description = "OWASP CRS rule IDs excluded only for application/grpc requests after confirmed HTTP/2/protobuf false positives."
  type        = set(string)
}

variable "waf_anomaly_threshold" {
  description = "OWASP CRS inbound anomaly score that produces a WAF deny verdict."
  type        = number

  validation {
    condition     = var.waf_anomaly_threshold >= 2 && var.waf_anomaly_threshold <= 10000 && floor(var.waf_anomaly_threshold) == var.waf_anomaly_threshold
    error_message = "waf_anomaly_threshold must be an integer from 2 to 10000."
  }
}
