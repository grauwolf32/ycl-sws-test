# Настройка и тьюнинг Smart Web Security/WAF

Этот гайд описывает безопасный рабочий цикл для текущего стенда и может быть
использован как шаблон для других сервисов. Профиль WAF всегда нужно калибровать
на реальном легитимном трафике конкретного приложения: универсального порога и
универсального списка исключений нет.

## Текущее рабочее состояние стенда

- активен `OWASP CRS 4.0.0`, paranoia level `1`, общий anomaly threshold `5`;
- `dry_run = false`: WAF работает в режиме enforcement;
- `/healthz`, `/readyz`, `/api...` и gRPC проверяются в режиме `API`, остальной
  трафик — в режиме `FULL`;
- анализируются первые `8 KiB` тела, превышение лимита блокируется (`DENY`);
- пишутся действия `ALLOW`, `DENY`, `CAPTCHA`, allow-семплирование выключено;
- `920280` отключено глобально из-за подтверждённого false positive на HTTP/2;
- пять protocol-правил OWASP исключены только для `application/grpc`, остальные
  сигнатуры продолжают проверять gRPC-запросы;
- оба профиля — OWASP и Yandex Ruleset — сохранены в Terraform, переключение
  меняет только ссылки в правилах профиля безопасности.

Итог последней проверки и сравнение наборов находятся в
[YANDEX_RULESET_COMPARISON_2026-08-28.md](YANDEX_RULESET_COMPARISON_2026-08-28.md).

## Как устроить правила

Правила профиля безопасности проверяются по приоритету: чем меньше число, тем
раньше правило. Поэтому сначала должны идти узкие служебные/API-условия, затем
catch-all для браузерного трафика. В текущей конфигурации это:

1. `/healthz` — WAF в режиме `API`;
2. `/readyz` — WAF в режиме `API`;
3. `Content-Type: application/grpc...` — WAF в режиме `API`;
4. `/api...` — WAF в режиме `API`;
5. остальной трафик — WAF в режиме `FULL`.

Режим `API` не отправляет клиента на CAPTCHA и подходит для машинных клиентов.
`FULL` применим к браузерному трафику. Условие `/api` следует проверять особенно
внимательно: prefix match также охватит `/apiary`; если это нежелательно,
разделите точный `/api` и префикс `/api/`.

В dry-run правило только пишет потенциальное решение и не останавливает поиск
следующего правила. Базовое действие в этот период должно оставаться `ALLOW`,
иначе трафик может быть заблокирован следующим правилом. Это поведение отдельно
отмечено в [официальном руководстве по базовой настройке](https://yandex.cloud/ru/docs/smartwebsecurity/tutorials/sws-basic-protection).

## Безопасный цикл изменений

### 1. Составьте карту трафика

До изменения правил зафиксируйте:

- хосты, пути, HTTP-методы и типы клиентов;
- query/header/body-поля, в которых допустимы HTML, SQL, shell-подобный текст,
  шаблоны, код или URL;
- `Content-Type`, максимальный размер тела, multipart/upload и streaming;
- HTTP/2, WebSocket, gRPC и нестандартные методы;
- критические операции: login, платежи, callback/webhook, admin и upload;
- ожидаемые origin-статусы: `404` или `405` приложения нельзя считать блоком
  WAF только по коду ответа.

Для разных классов трафика лучше создавать отдельные WAF-профили, когда их
требования заметно различаются. Не компенсируйте несовместимые upload/API и
browser-политики одним широким исключением.

### 2. Начните с режима только логирования

```bash
cd /home/ruslan/src/ycl-sws-test/terraform
terraform apply -var='sws_dry_run=true'
```

Во время калибровки сохраняйте все `ALLOW` (`discard_allow_percentage = 0`),
иначе нельзя корректно оценить долю false positive и отсутствие логов. Yandex
Cloud рекомендует проверять OWASP в dry-run не менее недели; для Yandex Ruleset
допускается более короткий период, но он всё равно должен охватывать будни,
выходные, фоновые задачи и пиковые сценарии. После каждого изменения правил
период наблюдения начинается заново. См. [рекомендации Yandex Cloud](https://yandex.cloud/ru/docs/smartwebsecurity/concepts/waf#recommendations).

Текущая retention лог-группы стенда — `72h`, поэтому для недельной production-
калибровки её нужно увеличить либо настроить безопасный экспорт агрегатов.

### 3. Прогоните воспроизводимую матрицу

```bash
cd /home/ruslan/src/ycl-sws-test/misc
go run ./wafcheck \
  -plan examples/sws-lab-ruleset-comparison.json \
  -target https://sws.grauwolf32.tech \
  -run-id "tune-$(date -u +%Y%m%dT%H%M%SZ)" \
  -parallel 1 \
  -output waf-report.json
```

Матрица должна содержать не только атаки, но и репрезентативный benign-набор:
реальные JSON/form/multipart, повторяющиеся query, код и естественный текст.
Запускайте тесты последовательно для чистого сравнения; нагрузочные испытания —
отдельным этапом и только в согласованное окно.

### 4. Коррелируйте HTTP с журналом SWS

Каждый запрос `wafcheck` получает `X-WAF-Test-ID`. Выгрузите только записи с
нужным префиксом и передайте их анализатору:

```bash
cd /home/ruslan/src/ycl-sws-test/misc
SWS_LOG_GROUP_ID="$(cd ../terraform && terraform output -json sws | jq -r .log_group_id)"
yc logging read \
  --group-id "$SWS_LOG_GROUP_ID" \
  --since 30m --limit 1000 --format json \
| go run ./swslog \
    -input - \
    -report waf-report.json \
    -request-id-prefix tune- \
    -output sws-analysis.json \
    -fail-on-empty -fail-on-missing -fail-on-conflict -fail-on-inconclusive
```

Для регулярного использования соберите `swslog` один раз и замените
`go run ./swslog` на путь к бинарнику. Чтобы не захватывать посторонний трафик,
экспорт можно предварительно отфильтровать по `X-WAF-Test-ID`.

Не полагайтесь только на временное окно: в проверке 28 августа часы клиента и
timestamp SWS отличались примерно на 4 минуты 37 секунд. Корреляционный маркер
надёжнее. Поля `waf_matched_rules` содержат `score`, `rule_id`, `rule_set_id` и
`rule_group_id`; схема описана в [документации логирования](https://yandex.cloud/ru/docs/smartwebsecurity/concepts/logging).

### 5. Классифицируйте результат

- **False positive:** легитимный запрос получил/получил бы `DENY`.
- **False negative:** контрольный атакующий запрос дошёл до origin.
- **Ниже порога:** в логе есть сигнатуры и score, но итог `ALLOW`. Можно
  исследовать порог, не меняя состав правил.
- **Нет сигнатуры:** `ALLOW`, score `0`, `waf_matched_rules` пуст. Снижение
  порога не поможет; нужен другой набор/версия правил или защита приложения.
- **Платформенная политика:** например, тело больше `8 KiB` блокируется без
  WAF-сигнатуры. Учитывайте её отдельно от качества rule set.
- **Origin error:** ответ с origin-маркером — решение приложения, даже если код
  `404`, `405` или `500`.

Полезные контрольные показатели: доля false positive по маршрутам, detection
rate тестовой матрицы, `allowed_with_waf_match`, `denied_without_waf_match`,
пропущенные логи, конфликты HTTP/log, top rule/group и распределение score.

## Как тюнить пороги

### OWASP CRS

У OWASP один общий порог и paranoia level для всего набора. Документация Yandex
Cloud рекомендует стартовать с `25`, после устранения false positive постепенно
снижать до `5`. Более высокий paranoia level добавляет сигнатуры и почти всегда
требует новый цикл dry-run.

На текущем стенде порог `5` оставлен намеренно. False positive на benign JSON
набрал `10`, но многие полезные детекты атак набрали только `5`. Поэтому поднять
общий порог до `11` означало бы потерять существенную часть покрытия. Для такого
случая нужен узкий exception на подтверждённые правила и конкретное поле/путь,
а не глобальное повышение порога.

### Yandex Ruleset

У Yandex Ruleset порог задаётся отдельно для каждой группы. Официальное
рекомендуемое начальное значение — `7`; paranoia level не используется.
Текущий Terraform включает все семь групп `CVE`, `LFI`, `RCE`, `RFI`, `SQLI`,
`Tool`, `XSS` с порогом `7`.

Критически важно включить сами группы. Во время проверки профиль с 129
включёнными сигнатурами, но без `rule_group`, разрешил четыре контрольных
XSS/SQLi/LFI/RCE-запроса.
Terraform теперь запрещает такую конфигурацию precondition'ом. Флаг
`yandex_ruleset_direct_blocking` предназначен только для контролируемого
исследования: direct-blocking обходит пороги и не подходит для production-
калибровки.

В текущей матрице benign SQL-текст дал score `10` в группе SQLI, а три SQLi-
атаки — `23`, `28` и `30`. Кандидат для следующего dry-run — поднять только
SQLI-порог до `11`, сохранив остальные группы на `7`:

```hcl
yandex_ruleset_rule_groups = {
  "yars-v0.1.1-attack-cve"  = {}
  "yars-v0.1.1-attack-lfi"  = {}
  "yars-v0.1.1-attack-rce"  = {}
  "yars-v0.1.1-attack-rfi"  = {}
  "yars-v0.1.1-attack-sqli" = { inbound_anomaly_threshold = 11 }
  "yars-v0.1.1-attack-tool" = {}
  "yars-v0.1.1-attack-xss"  = {}
}
```

Это гипотеза только по лабораторной выборке, не готовое production-значение.
Перед применением проверьте распределение score на реальном трафике и более
широком SQLi-корпусе. Не передавайте map только с одной группой: Terraform
заменит весь map. Текущая precondition отклонит конфигурацию, если отсутствует
хотя бы один из семи ожидаемых ключей.

Score разных rule set'ов не сравниваются напрямую: `10` в Yandex Ruleset не
эквивалентен `10` в OWASP CRS.

## Правила-исключения

Порядок безопасного исключения:

1. подтвердите false positive по request ID и воспроизведите его;
2. определите точные `rule_id`, `rule_group_id`, часть запроса и маршрут;
3. исключите только вызвавшие FP правила;
4. ограничьте условие хостом/путём/методом/`Content-Type`;
5. по возможности исключите конкретный query/header/cookie, а не весь запрос;
6. включите `log_excluded`, повторите benign и attack regression;
7. оставьте изменение в dry-run на полный период наблюдения.

Не делайте глобальное исключение SQLi/XSS для endpoint'а с пользовательским
вводом и не логируйте raw payload без необходимости. Yandex Cloud позволяет
исключать отдельные части запроса и рекомендует сохранять проверку остальных
частей; см. [описание исключений](https://yandex.cloud/ru/docs/smartwebsecurity/concepts/waf#exclusion-rules).

`swslog` намеренно не сохраняет `matched_data_value`, тела или исходные payload,
а IP по умолчанию маскирует. В сырых Cloud Logging эти данные могут быть
чувствительными — ограничьте IAM, retention и экспорт.

## Размер тела и uploads

`size_limit_action = DENY` предотвращает обход WAF добавлением padding, но на
этом стенде запрещает любой request body больше `8192` байт. Проверяйте границу
на допустимом для приложения `Content-Type`: пустой `text/plain` сам может
попасть под protocol/content-type правила и исказить результат.

Для реального upload лучше выделить отдельный host/route и профиль с лимитами
размера, аутентификацией, malware scanning и проверкой типа файла. `IGNORE`
означает, что URL/headers ещё анализируются, но лишняя часть body не защищена
сигнатурами; это осознанный риск, а не исправление WAF.

## gRPC и HTTP/2

OWASP CRS не декодирует protobuf по `.proto`: он видит HTTP/2-заголовки и байты
frame. На стенде правила `920180`, `920270`, `920280`, `920420`, `921150` дали
подтверждённые protocol false positive и исключены только при
`Content-Type: application/grpc`. XSS/SQLi/LFI/RCE остаются активными.

Yandex Cloud отдельно предупреждает о false positive `920280` на HTTP/2.
Исключение WAF не заменяет application-level authentication, authorization,
rate limiting, protobuf validation и ограничения размера/частоты streaming.

## Переключение, enforcement и rollback

Безопасная проверка Yandex Ruleset:

```bash
cd /home/ruslan/src/ycl-sws-test/terraform
terraform apply \
  -var='waf_active_ruleset=YANDEX_RULESET' \
  -var='sws_dry_run=true'
```

После dry-run, корреляции и согласованного canary можно включить enforcement:

```bash
terraform apply \
  -var='waf_active_ruleset=YANDEX_RULESET' \
  -var='sws_dry_run=false'
```

Rollback на проверенную конфигурацию:

```bash
terraform apply \
  -var='waf_active_ruleset=OWASP_CRS' \
  -var='sws_dry_run=false'
```

После каждого apply проверьте `terraform output -json sws`, benign health/API,
один гарантированно блокируемый XSS-кейс, корреляцию логов и затем
`terraform plan -detailed-exitcode`. Не считайте apply завершённым, пока профиль
не вернулся в ожидаемое состояние и plan не показывает нулевой drift.

## Go/no-go checklist

- все критические маршруты присутствуют в benign-наборе;
- dry-run охватил полный бизнес-цикл и пики;
- у всех ожидаемых тестов есть SWS-лог и нет HTTP/log conflicts;
- каждый false positive устранён узко и имеет regression case;
- нет необъяснённых `DENY` без WAF-сигнатуры;
- у каждого разрешённого attack case понятна причина: score ниже порога или
  сигнатуры нет;
- body limit, API/FULL и CAPTCHA проверены отдельно;
- есть измеримые SLO/alert'ы на DENY/CAPTCHA, false positive и log gaps;
- rollback-команда и предыдущий профиль проверены;
- после обновления версии rule set выполнен новый dry-run и полный regression.

Версии rule set следует закреплять явно. По состоянию на 28 августа 2026 года
документация SWS также перечисляет OWASP CRS `4.8.0`, но текущий профиль и этот
отчёт используют `4.0.0`; обновление до `4.8.0` нужно тестировать как отдельное
изменение. Yandex Ruleset `0.1.1` содержит 129 правил и всё ещё относится к
Preview-наборам, согласно [документации WAF](https://yandex.cloud/ru/docs/smartwebsecurity/concepts/waf).
