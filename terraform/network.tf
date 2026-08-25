resource "yandex_vpc_network" "default" {
  name        = var.network_name
  description = "Network for the SWS test environment"
}

resource "yandex_vpc_subnet" "default_a" {
  name           = "sws-test-ru-central1-a"
  description    = "SWS test subnet in ru-central1-a"
  zone           = "ru-central1-a"
  network_id     = yandex_vpc_network.default.id
  v4_cidr_blocks = [var.subnet_cidrs.a]
}

resource "yandex_vpc_subnet" "default_b" {
  name           = "sws-test-ru-central1-b"
  description    = "SWS test subnet in ru-central1-b"
  zone           = "ru-central1-b"
  network_id     = yandex_vpc_network.default.id
  v4_cidr_blocks = [var.subnet_cidrs.b]
}
