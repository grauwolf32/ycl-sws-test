resource "yandex_vpc_address" "backend_a" {
  name        = "backend-a-public-ip"
  description = "Static public IPv4 address for SSH access to backend A"

  external_ipv4_address {
    zone_id = "ru-central1-a"
  }
}

resource "yandex_vpc_address" "backend_b" {
  name        = "backend-b-public-ip"
  description = "Static public IPv4 address for SSH access to backend B"

  external_ipv4_address {
    zone_id = "ru-central1-b"
  }
}
