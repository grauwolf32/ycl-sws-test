data "yandex_compute_image" "ubuntu" {
  family = var.image_family
}

locals {
  ssh_public_key = trimspace(coalesce(
    var.ssh_public_key,
    file("${path.module}/files/ssh/r-bomin-rsa.pub"),
  ))
  ssh_public_keys = [
    local.ssh_public_key,
    trimspace(file("${path.module}/files/ssh/ansible-deploy.pub")),
  ]
}

resource "yandex_compute_instance" "vm_a" {
  name        = var.vm_a.name
  hostname    = var.vm_a.name
  platform_id = "standard-v3"
  zone        = "ru-central1-a"

  resources {
    cores         = 2
    memory        = 2
    core_fraction = 100
  }

  boot_disk {
    auto_delete = true

    initialize_params {
      name     = "${var.vm_a.name}-boot"
      image_id = data.yandex_compute_image.ubuntu.id
      type     = "network-hdd"
      size     = 20
    }
  }

  network_interface {
    subnet_id      = yandex_vpc_subnet.default_a.id
    nat            = true
    nat_ip_address = yandex_vpc_address.backend_a.external_ipv4_address[0].address
    security_group_ids = [
      yandex_vpc_security_group.backend.id,
    ]
  }

  metadata = {
    "user-data" = templatefile("${path.module}/cloud-init/backend.yaml.tftpl", {
      ssh_public_keys = local.ssh_public_keys
      ssh_user        = var.vm_a.ssh_user
    })
  }

  lifecycle {
    # Existing VMs retain their original image while a fresh deployment uses
    # the current READY image from image_family.
    ignore_changes = [boot_disk[0].initialize_params[0].image_id]
  }
}

resource "yandex_compute_instance" "vm_b" {
  name        = var.vm_b.name
  hostname    = var.vm_b.name
  platform_id = "standard-v3"
  zone        = "ru-central1-b"

  resources {
    cores         = 2
    memory        = 2
    core_fraction = 100
  }

  boot_disk {
    auto_delete = true

    initialize_params {
      name     = "${var.vm_b.name}-boot"
      image_id = data.yandex_compute_image.ubuntu.id
      type     = "network-hdd"
      size     = 20
    }
  }

  network_interface {
    subnet_id      = yandex_vpc_subnet.default_b.id
    nat            = true
    nat_ip_address = yandex_vpc_address.backend_b.external_ipv4_address[0].address
    security_group_ids = [
      yandex_vpc_security_group.backend.id,
    ]
  }

  metadata = {
    "user-data" = templatefile("${path.module}/cloud-init/backend.yaml.tftpl", {
      ssh_public_keys = local.ssh_public_keys
      ssh_user        = var.vm_b.ssh_user
    })
  }

  lifecycle {
    ignore_changes = [boot_disk[0].initialize_params[0].image_id]
  }
}
