variable "network_name" {
  description = "VPC network name."
  type        = string
  default     = "sws-test"
}

variable "subnet_cidrs" {
  description = "IPv4 CIDRs keyed by availability zone suffix."
  type        = map(string)
  default = {
    a = "10.128.0.0/24"
    b = "10.129.0.0/24"
  }
}

variable "image_family" {
  description = "Public image family used for newly created VM boot disks."
  type        = string
  default     = "ubuntu-2404-lts"
}

variable "ssh_public_key" {
  description = "Optional SSH public key override. The checked-in RSA public key is used when null."
  type        = string
  default     = null

  validation {
    condition     = var.ssh_public_key == null || can(regex("^ssh-(ed25519|rsa) ", trimspace(var.ssh_public_key)))
    error_message = "ssh_public_key must be an OpenSSH ed25519 or RSA public key."
  }
}

variable "admin_cidrs" {
  description = "Public IPv4 /32 CIDRs allowed to connect to backend VMs over SSH."
  type        = set(string)

  validation {
    condition = length(var.admin_cidrs) > 0 && alltrue([
      for cidr in var.admin_cidrs :
      can(cidrhost(cidr, 0)) && can(regex("^[0-9]{1,3}(\\.[0-9]{1,3}){3}/32$", cidr))
    ])
    error_message = "admin_cidrs must contain at least one valid IPv4 /32 CIDR."
  }
}

variable "vm_a" {
  description = "Settings for the VM in ru-central1-a."
  type = object({
    name     = string
    ssh_user = string
  })
  default = {
    name     = "sws-backend-a"
    ssh_user = "grauwolf"
  }
}

variable "vm_b" {
  description = "Settings for the VM in ru-central1-b."
  type = object({
    name     = string
    ssh_user = string
  })
  default = {
    name     = "sws-backend-b"
    ssh_user = "grauwolf"
  }
}

variable "alb_public_ip_name" {
  description = "Name of the reserved public IPv4 address used by the ALB."
  type        = string
  default     = "sws-alb-public-ip"
}

variable "domain_name" {
  description = "Public DNS name served by the ALB and covered by its managed certificate."
  type        = string
  default     = "sws.grauwolf32.tech"

  validation {
    condition     = length(trimspace(var.domain_name)) > 0 && !endswith(var.domain_name, ".")
    error_message = "domain_name must be a non-empty FQDN without a trailing dot."
  }
}

variable "sws_dry_run" {
  description = "Run SWS WAF rules in logging-only mode without affecting traffic."
  type        = bool
  default     = true
}

variable "waf_active_ruleset" {
  description = "Managed WAF rule set attached to SWS: OWASP_CRS or YANDEX_RULESET."
  type        = string
  default     = "OWASP_CRS"

  validation {
    condition     = contains(["OWASP_CRS", "YANDEX_RULESET"], var.waf_active_ruleset)
    error_message = "waf_active_ruleset must be OWASP_CRS or YANDEX_RULESET."
  }
}

variable "yandex_ruleset_direct_blocking" {
  description = "Make every enabled Yandex Ruleset signature blocking; intended only for controlled rule-group discovery."
  type        = bool
  default     = false
}

variable "yandex_ruleset_rule_groups" {
  description = "Yandex Ruleset group settings keyed by the opaque group ID returned in SWS logs."
  type = map(object({
    action                    = optional(string, "DENY")
    inbound_anomaly_threshold = optional(number, 7)
    is_enabled                = optional(bool, true)
  }))
  default = {
    "yars-v0.1.1-attack-cve"  = {}
    "yars-v0.1.1-attack-lfi"  = {}
    "yars-v0.1.1-attack-rce"  = {}
    "yars-v0.1.1-attack-rfi"  = {}
    "yars-v0.1.1-attack-sqli" = {}
    "yars-v0.1.1-attack-tool" = {}
    "yars-v0.1.1-attack-xss"  = {}
  }

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

variable "sws_api_path_prefix" {
  description = "Request path prefix protected in API mode without CAPTCHA redirects."
  type        = string
  default     = "/api"

  validation {
    condition     = startswith(var.sws_api_path_prefix, "/") && !strcontains(var.sws_api_path_prefix, "?") && !strcontains(var.sws_api_path_prefix, "#")
    error_message = "sws_api_path_prefix must be an absolute request path without a query string or fragment."
  }
}

variable "grpc_backend_port" {
  description = "TCP port exposed by backend VMs for native gRPC traffic."
  type        = number
  default     = 9090

  validation {
    condition     = var.grpc_backend_port >= 1 && var.grpc_backend_port <= 65535 && floor(var.grpc_backend_port) == var.grpc_backend_port
    error_message = "grpc_backend_port must be an integer from 1 to 65535."
  }
}

variable "waf_body_size_limit_kb" {
  description = "Maximum request body size inspected by SWS, in KiB."
  type        = number
  default     = 8

  validation {
    condition     = var.waf_body_size_limit_kb >= 1 && var.waf_body_size_limit_kb <= 8 && floor(var.waf_body_size_limit_kb) == var.waf_body_size_limit_kb
    error_message = "waf_body_size_limit_kb must be an integer from 1 to 8."
  }
}

variable "waf_body_size_limit_action" {
  description = "SWS action when a request body exceeds the inspection limit: IGNORE or DENY."
  type        = string
  default     = "DENY"

  validation {
    condition     = contains(["IGNORE", "DENY"], var.waf_body_size_limit_action)
    error_message = "waf_body_size_limit_action must be IGNORE or DENY."
  }
}

variable "waf_paranoia_level" {
  description = "Maximum OWASP CRS paranoia level whose rules are enabled."
  type        = number
  default     = 1

  validation {
    condition     = var.waf_paranoia_level >= 1 && var.waf_paranoia_level <= 4 && floor(var.waf_paranoia_level) == var.waf_paranoia_level
    error_message = "waf_paranoia_level must be an integer from 1 to 4."
  }
}

variable "waf_disabled_rule_ids" {
  description = "OWASP CRS rule IDs disabled globally after confirmed protocol false positives."
  type        = set(string)
  default = [
    "owasp-crs-v4.0.0-id920280-protocol-enforcement",
  ]
}

variable "waf_grpc_excluded_rule_ids" {
  description = "OWASP CRS rule IDs excluded only for application/grpc requests after confirmed HTTP/2/protobuf false positives."
  type        = set(string)
  default = [
    "owasp-crs-v4.0.0-id920180-protocol-enforcement",
    "owasp-crs-v4.0.0-id920270-protocol-enforcement",
    "owasp-crs-v4.0.0-id920280-protocol-enforcement",
    "owasp-crs-v4.0.0-id920420-protocol-enforcement",
    "owasp-crs-v4.0.0-id921150-protocol-attack",
  ]
}

variable "waf_anomaly_threshold" {
  description = "OWASP CRS inbound anomaly score that produces a WAF deny verdict."
  type        = number
  default     = 5

  validation {
    condition     = var.waf_anomaly_threshold >= 2 && var.waf_anomaly_threshold <= 10000 && floor(var.waf_anomaly_threshold) == var.waf_anomaly_threshold
    error_message = "waf_anomaly_threshold must be an integer from 2 to 10000."
  }
}
