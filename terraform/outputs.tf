output "alb_public_ip" {
  description = "Reserved public IPv4 address of the Application Load Balancer."
  value       = yandex_vpc_address.alb.external_ipv4_address[0].address
}

output "https_url" {
  description = "Public HTTPS URL served by the Application Load Balancer."
  value       = "https://${var.domain_name}"
}

output "tls_certificate" {
  description = "Managed Certificate Manager certificate attached to the HTTPS listener."
  value = {
    id        = yandex_cm_certificate.sws.id
    domains   = yandex_cm_certificate.sws.domains
    status    = yandex_cm_certificate.sws.status
    not_after = yandex_cm_certificate.sws.not_after
  }
}

output "vm_private_ips" {
  description = "Private IPv4 addresses of the backend VMs."
  value = {
    a = yandex_compute_instance.vm_a.network_interface[0].ip_address
    b = yandex_compute_instance.vm_b.network_interface[0].ip_address
  }
}

output "vm_public_ips" {
  description = "Public IPv4 addresses currently assigned to backend VM interfaces."
  value = {
    a = yandex_compute_instance.vm_a.network_interface[0].nat_ip_address
    b = yandex_compute_instance.vm_b.network_interface[0].nat_ip_address
  }
}

output "ssh_commands" {
  description = "SSH commands for the backend VMs. Access is restricted by admin_cidrs."
  value = {
    a = "ssh ${var.vm_a.ssh_user}@${yandex_compute_instance.vm_a.network_interface[0].nat_ip_address}"
    b = "ssh ${var.vm_b.ssh_user}@${yandex_compute_instance.vm_b.network_interface[0].nat_ip_address}"
  }
}

output "sws" {
  description = "Smart Web Security resources and rollout mode."
  value = {
    security_profile_id = yandex_sws_security_profile.test.id
    waf_profile_id      = yandex_sws_waf_profile.test.id
    log_group_id        = yandex_logging_group.sws.id
    dry_run             = var.sws_dry_run
  }
}
