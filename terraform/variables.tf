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
  description = "Run Smart Protection and WAF rules in logging-only mode without affecting traffic."
  type        = bool
  default     = true
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

variable "waf_anomaly_threshold" {
  description = "OWASP CRS inbound anomaly score that produces a WAF deny verdict."
  type        = number
  default     = 25

  validation {
    condition     = var.waf_anomaly_threshold >= 2 && var.waf_anomaly_threshold <= 10000 && floor(var.waf_anomaly_threshold) == var.waf_anomaly_threshold
    error_message = "waf_anomaly_threshold must be an integer from 2 to 10000."
  }
}
