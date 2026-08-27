output "alb_security_group_id" {
  description = "Security group attached to the Application Load Balancer."
  value       = yandex_vpc_security_group.alb.id
}

output "backend_security_group_id" {
  description = "Security group attached to backend VM interfaces."
  value       = yandex_vpc_security_group.backend.id
}

output "sws_security_profile_id" {
  description = "Smart Web Security profile attached to the ALB virtual host."
  value       = yandex_sws_security_profile.test.id
}

output "waf_profile_id" {
  description = "Active managed WAF profile used by Smart Web Security."
  value       = local.active_waf_profile_id
}

output "owasp_waf_profile_id" {
  description = "OWASP CRS WAF profile available for comparison."
  value       = yandex_sws_waf_profile.test.id
}

output "yandex_waf_profile_id" {
  description = "Yandex Ruleset WAF profile available for comparison."
  value       = yandex_sws_waf_profile.yandex.id
}

output "log_group_id" {
  description = "Cloud Logging group receiving Smart Web Security logs."
  value       = yandex_logging_group.sws.id
}
