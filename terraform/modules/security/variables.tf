variable "network_id" {
  description = "VPC network that owns the security groups."
  type        = string
}

variable "admin_cidrs" {
  description = "Public IPv4 /32 CIDRs allowed to connect to backend VMs over SSH."
  type        = set(string)
}

variable "sws_dry_run" {
  description = "Run Smart Protection and WAF rules in logging-only mode without affecting traffic."
  type        = bool
}

variable "waf_paranoia_level" {
  description = "Maximum OWASP CRS paranoia level whose rules are enabled."
  type        = number

  validation {
    condition     = var.waf_paranoia_level >= 1 && var.waf_paranoia_level <= 4 && floor(var.waf_paranoia_level) == var.waf_paranoia_level
    error_message = "waf_paranoia_level must be an integer from 1 to 4."
  }
}

variable "waf_anomaly_threshold" {
  description = "OWASP CRS inbound anomaly score that produces a WAF deny verdict."
  type        = number

  validation {
    condition     = var.waf_anomaly_threshold >= 2 && var.waf_anomaly_threshold <= 10000 && floor(var.waf_anomaly_threshold) == var.waf_anomaly_threshold
    error_message = "waf_anomaly_threshold must be an integer from 2 to 10000."
  }
}
