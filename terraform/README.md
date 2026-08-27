# Yandex Cloud Terraform

Чистое воспроизводимое окружение для тестового приложения:

- отдельная VPC и две подсети в `ru-central1-a/b`;
- две Ubuntu 24.04 backend VM со статическими публичными IP;
- минимальный cloud-init с локальными SSH-пользователями и одним публичным ключом;
- отдельные `alb-sg` и `backend-sg`;
- Application Load Balancer с HTTP listener на порту `80` и HTTPS listener на
  порту `443`;
- управляемый сертификат Let's Encrypt для `sws.grauwolf32.tech`;
- target group, отдельные HTTP/gRPC backend groups, HTTP router и virtual host;
- gRPC route на backend-порт `9090` в том же virtual host;
- Smart Web Security с переключаемыми OWASP CRS/Yandex Ruleset WAF-профилями:
  API-защита без CAPTCHA для `/api/**` и gRPC, полная защита для остального
  трафика.

Backend принимает HTTP и gRPC только от `alb-sg`, а SSH — только из адресов
`admin_cidrs`. Egress пока намеренно не ограничен.

## Состав

- `network.tf`: VPC и две подсети;
- `security.tf`: подключение локального модуля политик безопасности;
- `modules/security/`: default/ALB/backend SG, WAF, SWS и лог-группа;
- `public-access.tf`: три статических публичных IPv4;
- `compute.tf`: две VM с auto-delete boot-дисками;
- `alb.tf`: ALB и объекты маршрутизации;
- `certificate.tf`: управляемый сертификат Certificate Manager;
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

Правила WAF по умолчанию работают в режиме `dry_run`: запросы не блокируются, а
срабатывания записываются в Cloud Logging. Запросы с префиксом `/api` и
`Content-Type: application/grpc`, `/healthz` и `/readyz` проверяются в режиме
`API` без перенаправления на CAPTCHA, остальные — в режиме `FULL`. WAF стартует
с OWASP CRS 4.0, paranoia
level `1` и порогом аномальности `5`. Правило `920280` отключено из-за
подтверждённого ложного срабатывания на HTTP/2. Для gRPC узко исключены пять
protocol-enforcement правил, ложно распознающих HTTP/2/protobuf framing как
отсутствие заголовков, null/CRLF injection или недопустимый Content-Type;
XSS/SQLi/LFI/RCE-сигнатуры продолжают применяться.

Переменная `sws_dry_run` по умолчанию безопасно равна `true`, но текущий стенд
после калибровки 27 августа 2026 года закрепляет `false` в `terraform.tfvars`.
Для временного возврата только к журналированию используйте:

```bash
terraform apply -var='sws_dry_run=true'
```

SWS анализирует первые `8` КиБ тела запроса. Для более крупных тел выбран
безопасный default `DENY`: пока соответствующее WAF-правило работает в
`dry_run`, запрос всё ещё проходит, а после включения enforcement SWS вернёт
`403`. Это предотвращает обход body inspection добавлением padding, но
ограничивает multipart/upload API. Превышение этого профильного лимита не всегда
создаёт отдельное dry-run событие, поэтому перед общим включением блокировки
нужен короткий контролируемый тест.

Если для отдельного API действительно нужны большие тела, временно переключить
поведение можно так:

```bash
terraform apply -var='waf_body_size_limit_action=IGNORE'
```

При `IGNORE` WAF продолжит проверять URL и заголовки, но не содержимое слишком
большого тела. Предпочтительнее вынести большой upload на отдельный virtual host
с собственным профилем и компенсирующими ограничениями. Лимит анализа и действие
задаются переменными `waf_body_size_limit_kb` и
`waf_body_size_limit_action`; допустимый максимум анализа SWS — 8 КиБ.

## Выбор managed rule set

Terraform создаёт два независимых WAF-профиля и подключает к правилам SWS один
из них через `waf_active_ruleset`:

- `OWASP_CRS` — OWASP CRS 4.0.0, PL1, общий threshold `5`;
- `YANDEX_RULESET` — Yandex Ruleset 0.1.1, все 129 правил и семь групп с
  отдельным threshold `7`.

По умолчанию и в текущем рабочем состоянии активен `OWASP_CRS`. Безопасный
пробный запуск Yandex Ruleset выполняется только в dry-run:

```bash
terraform apply \
  -var='waf_active_ruleset=YANDEX_RULESET' \
  -var='sws_dry_run=true'
```

После проверки верните рабочий профиль:

```bash
terraform apply \
  -var='waf_active_ruleset=OWASP_CRS' \
  -var='sws_dry_run=false'
```

Не удаляйте ключи из `yandex_ruleset_rule_groups`: без включённых групп
сигнатуры Yandex Ruleset не формируют ожидаемый групповой verdict. Lifecycle-
precondition требует явных настроек для всех семи групп; нужную группу можно
осознанно выключить через `is_enabled = false`. `yandex_ruleset_direct_blocking=true`
обходит anomaly thresholds и предназначен только для контролируемого discovery,
не для production.

Точная методика настройки и rollback описаны в
[`../SWS_TUNING_GUIDE.md`](../SWS_TUNING_GUIDE.md), результаты A/B-теста — в
[`../YANDEX_RULESET_COMPARISON_2026-08-28.md`](../YANDEX_RULESET_COMPARISON_2026-08-28.md).

HTTP и HTTPS используют один HTTP router и virtual host, поэтому к обоим
протоколам применяется один и тот же профиль Smart Web Security. Для
автоматического продления сертификата оставьте у внешнего DNS-провайдера CNAME
`_acme-challenge.sws.grauwolf32.tech` на значение, выданное Certificate Manager.

gRPC использует тот же HTTPS listener, сертификат, HTTP router, virtual host и
профиль SWS. Отдельный router не требуется; публичная точка подключения
выводится командой `terraform output grpc_target`.

OWASP CRS не декодирует protobuf по `.proto`-схеме: WAF эвристически проверяет
HTTP/2 headers и байты gRPC frame. Это помогает обнаруживать текстовые маркеры,
но может давать протокольные false positive и не заменяет gRPC-аутентификацию,
авторизацию, rate limiting и валидацию сообщений в приложении. Перед отключением
`dry_run` соберите benign gRPC-трафик и добавляйте только узкие исключения для
подтверждённых ложных срабатываний.

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
- правила SWS WAF по умолчанию не блокируют трафик (`dry_run = true`);
- ALB и backend VM имеют unrestricted egress;
- обе backend VM имеют публичные IP для прямого SSH;
- Terraform state локальный; для совместной работы нужен remote backend.

Приложение развёртывается отдельно конфигурацией из соседнего каталога
`../ansible`.
