resource "yandex_cm_certificate" "sws" {
  name        = replace(var.domain_name, ".", "-")
  description = "Managed Let's Encrypt certificate for ${var.domain_name}"
  domains     = [var.domain_name]

  managed {
    # Keep the CNAME challenge in external DNS so Certificate Manager can
    # renew the certificate without changing records at the DNS provider.
    challenge_type = "DNS_CNAME"
  }
}
