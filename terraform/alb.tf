resource "yandex_vpc_address" "alb" {
  name        = var.alb_public_ip_name
  description = "Static public IPv4 address for the SWS test ALB"

  external_ipv4_address {
    zone_id = "ru-central1-b"
  }

  lifecycle {
    # Keep the listener address allocated while Terraform switches the ALB to
    # its replacement. This requires one temporary spare static-IP quota slot.
    create_before_destroy = true
  }
}

resource "yandex_alb_target_group" "test" {
  name = "test-target-group"

  target {
    subnet_id  = yandex_vpc_subnet.default_b.id
    ip_address = yandex_compute_instance.vm_b.network_interface[0].ip_address
  }

  target {
    subnet_id  = yandex_vpc_subnet.default_a.id
    ip_address = yandex_compute_instance.vm_a.network_interface[0].ip_address
  }
}

resource "yandex_alb_backend_group" "test" {
  name = "test-backend-group"

  http_backend {
    name             = "gw-test-backends"
    weight           = 1
    port             = 80
    target_group_ids = [yandex_alb_target_group.test.id]

    load_balancing_config {
      mode = "ROUND_ROBIN"
    }

    healthcheck {
      timeout             = "2s"
      interval            = "5s"
      healthy_threshold   = 2
      unhealthy_threshold = 2
      healthcheck_port    = 80

      http_healthcheck {
        path = "/"
      }
    }
  }
}

resource "yandex_alb_http_router" "test" {
  name        = "test-http-router"
  description = "Routes the public ALB listener to the test backend group"
}

resource "yandex_alb_virtual_host" "test" {
  name           = "test-virtual-host"
  http_router_id = yandex_alb_http_router.test.id
  authority      = [var.domain_name]

  route_options {
    security_profile_id = module.security.sws_security_profile_id
  }

  route {
    name = "all-to-test-backends"

    http_route {
      http_match {
        path {
          prefix = "/"
        }
      }

      http_route_action {
        backend_group_id = yandex_alb_backend_group.test.id
      }
    }
  }
}

resource "yandex_alb_load_balancer" "test" {
  name               = "alb-test"
  network_id         = yandex_vpc_network.default.id
  region_id          = "ru-central1"
  security_group_ids = [module.security.alb_security_group_id]

  allocation_policy {
    location {
      zone_id   = "ru-central1-a"
      subnet_id = yandex_vpc_subnet.default_a.id
    }

    location {
      zone_id   = "ru-central1-b"
      subnet_id = yandex_vpc_subnet.default_b.id
    }
  }

  auto_scale_policy {
    min_zone_size = 2
    max_size      = 4
  }

  listener {
    name = "test-alb-listener"

    endpoint {
      ports = [80]

      address {
        external_ipv4_address {
          address = yandex_vpc_address.alb.external_ipv4_address[0].address
        }
      }
    }

    http {
      handler {
        http_router_id = yandex_alb_http_router.test.id
      }
    }
  }

  listener {
    name = "sws-https-listener"

    endpoint {
      ports = [443]

      address {
        external_ipv4_address {
          address = yandex_vpc_address.alb.external_ipv4_address[0].address
        }
      }
    }

    tls {
      default_handler {
        certificate_ids = [yandex_cm_certificate.sws.id]

        # Both listeners use this router. The SWS profile attached to its
        # virtual host therefore protects HTTP and HTTPS identically.
        http_handler {
          http_router_id = yandex_alb_http_router.test.id
        }
      }
    }
  }

  log_options {
    disable = false
  }
}
