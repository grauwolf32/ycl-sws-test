resource "yandex_vpc_security_group" "alb" {
  name        = "alb-sg"
  description = "Public listener, ALB node health checks, and unrestricted egress"
  network_id  = yandex_vpc_network.default.id

  ingress {
    description    = "Public listener"
    protocol       = "TCP"
    port           = 80
    v4_cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description    = "Public HTTPS listener"
    protocol       = "TCP"
    port           = 443
    v4_cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description       = "ALB node health checks"
    protocol          = "TCP"
    port              = 30080
    predefined_target = "loadbalancer_healthchecks"
  }

  egress {
    description    = "Unrestricted egress"
    protocol       = "ANY"
    v4_cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "yandex_vpc_security_group" "backend" {
  name        = "backend-sg"
  description = "Backend HTTP from ALB and SSH from administrator addresses"
  network_id  = yandex_vpc_network.default.id

  ingress {
    description       = "Application traffic and backend health checks from ALB"
    protocol          = "TCP"
    port              = 80
    security_group_id = yandex_vpc_security_group.alb.id
  }

  ingress {
    description    = "SSH from administrator addresses"
    protocol       = "TCP"
    port           = 22
    v4_cidr_blocks = sort(tolist(var.admin_cidrs))
  }

  egress {
    description    = "Unrestricted egress"
    protocol       = "ANY"
    v4_cidr_blocks = ["0.0.0.0/0"]
  }
}
