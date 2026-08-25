# Yandex Cloud Terraform

Чистое воспроизводимое окружение для тестового приложения:

- отдельная VPC и две подсети в `ru-central1-a/b`;
- две Ubuntu 24.04 backend VM со статическими публичными IP;
- минимальный cloud-init с локальными SSH-пользователями и одним публичным ключом;
- отдельные `alb-sg` и `backend-sg`;
- Application Load Balancer с HTTP listener на порту `80` и HTTPS listener на
  порту `443`;
- управляемый сертификат Let's Encrypt для `sws.grauwolf32.tech`;
- target group, backend group, HTTP router и virtual host;
- Smart Web Security с Smart Protection и OWASP CRS WAF.

Backend принимает HTTP только от `alb-sg`, а SSH — только из адресов
`admin_cidrs`. Egress пока намеренно не ограничен.

## Состав

- `network.tf`: VPC, две подсети и управляемая default SG без ingress;
- `security-groups.tf`: правила ALB и backend VM;
- `public-access.tf`: три статических публичных IPv4;
- `compute.tf`: две VM с auto-delete boot-дисками;
- `alb.tf`: ALB и объекты маршрутизации;
- `certificate.tf`: управляемый сертификат Certificate Manager;
- `sws.tf`: WAF, профиль безопасности и отдельная лог-группа;
- `cloud-init/backend.yaml.tftpl`: пользователь, `sudo` и SSH-ключ;
- `variables.tf` и `terraform.tfvars`: переносимые параметры;
- `outputs.tf`: адрес ALB, адреса VM и SSH-команды.

## Аутентификация

Credentials в HCL не хранятся. Провайдер читает их из окружения:

```bash
cd /home/ruslan/src/ycl-sws-test/terraform
export PATH="$PWD/.tools/bin:$PATH"
export YC_CLOUD_ID="b1g5d67ff4lk052s8jmb"
export YC_FOLDER_ID="b1g4fbgu2qebbsdr0jun"
export TF_SA_ID="ajekhfd2cjghh4n2b451"
export YC_TOKEN="$(yc iam create-token \
  --impersonate-service-account-id "$TF_SA_ID")"
```

## Проверка и применение

```bash
terraform init
terraform fmt -check -recursive
terraform validate
terraform plan
terraform apply
terraform output
```

Smart Protection и WAF по умолчанию работают в режиме `dry_run`: запросы не
блокируются, а срабатывания записываются в Cloud Logging. WAF стартует с OWASP
CRS 4.0, paranoia level `1` и порогом аномальности `25`. После анализа логов и
настройки исключений защиту можно включить явно:

```bash
terraform apply -var='sws_dry_run=false'
```

HTTP и HTTPS используют один HTTP router и virtual host, поэтому к обоим
протоколам применяется один и тот же профиль Smart Web Security. Для
автоматического продления сертификата оставьте у внешнего DNS-провайдера CNAME
`_acme-challenge.sws.grauwolf32.tech` на значение, выданное Certificate Manager.

По умолчанию используется обычный образ `ubuntu-2404-lts`, а не OS Login
image. Пользовательский RSA-ключ находится в `files/ssh/r-bomin-rsa.pub`, а
публичная часть отдельного Ansible-ключа — в `files/ssh/ansible-deploy.pub`.
Пользовательский ключ можно переопределить без изменения кода:

```bash
terraform apply \
  -var='ssh_public_key=ssh-ed25519 AAAA... user@host'
```

После создания используйте команды из output:

```bash
terraform output ssh_commands
```

## Ограничения тестового окружения

- HTTP на порту `80` пока доступен без перенаправления на HTTPS;
- Smart Protection и WAF по умолчанию не блокируют трафик (`dry_run = true`);
- ALB и backend VM имеют unrestricted egress;
- обе backend VM имеют публичные IP для прямого SSH;
- Terraform state локальный; для совместной работы нужен remote backend.

Приложение развёртывается отдельно конфигурацией из соседнего каталога
`../ansible`.
