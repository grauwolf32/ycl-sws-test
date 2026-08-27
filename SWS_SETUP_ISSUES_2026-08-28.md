# Проблемы и баги, обнаруженные при настройке SWS/WAF

Дата фиксации: **28 августа 2026 года**. Документ описывает фактические
проблемы, найденные при переводе стенда `sws.grauwolf32.tech` в enforcement,
настройке HTTP/gRPC, анализе журналов и сравнении OWASP CRS 4.0.0 с Yandex
Ruleset 0.1.1.

Это не перечень общих недостатков Smart Web Security. Ниже отдельно отмечено,
что было:

- подтверждённой опасной ловушкой конфигурации;
- несовместимостью generic WAF с протоколом приложения;
- ограничением или ожидаемым поведением платформы;
- ошибкой первоначальной методики тестирования;
- пробелом покрытия конкретного rule set.

Исходные raw-логи не добавлены в Git: в них присутствуют IP, query/header
values и `matched_data_value`. В репозитории сохранены обезличенные агрегаты и
корреляция каждого финального запроса с решением SWS.

## Краткий итог

Самая опасная находка — **Yandex Ruleset мог быть создан с включёнными 129
сигнатурами, но без `rule_group`, и фактически пропускал контрольные атаки со
score 0**. API и Terraform provider приняли профиль без ошибки. Это
fail-open-конфигурация: внешне профиль существует и правила включены, но
ожидаемой защиты нет. В коде добавлены все семь групп и Terraform precondition,
который не позволяет повторить эту конфигурацию.

Самая существенная проблема совместимости — **OWASP CRS считал нормальные
gRPC-запросы нарушениями HTTP-протокола**. Benign gRPC набирал score 16–21 при
целевом пороге 5. Пять правил исключены только для
`Content-Type: application/grpc...`; после этого benign gRPC получил score 0,
а XSS-маркер в gRPC сохранил три сигнатуры и score 15.

Наибольшее число ложных выводов при тестировании дали три вещи:

1. raw-body тесты одновременно нарушали content-type policy и поэтому не
   измеряли границу размера тела;
2. HTTP `404`/`405` origin, edge `403` и CAPTCHA `302` нельзя различить только
   по классу status code;
3. временная корреляция оказалась ненадёжной из-за расхождения часов примерно
   на 4 минуты 37 секунд и постороннего фонового трафика.

Текущее состояние безопасно возвращено на OWASP CRS 4.0.0, PL1, threshold 5,
`dry_run = false`. Terraform не имеет drift, HTTP и gRPC backends здоровы.
Известные false positive и пропуски сигнатур перечислены ниже и остаются
предметом следующего dry-run-тюнинга.

## Сводка проблем

| № | Наблюдение | Класс | Риск до исправления | Статус |
|---:|---|---|---|---|
| 1 | Yandex Ruleset без `rule_group` пропускал все probes | fail-open ловушка, кандидат на дефект API-валидации | высокий | закрыто защитой в Terraform; платформенный риск остаётся |
| 2 | IDs групп Yandex Ruleset нельзя получить из descriptor | пробел API/provider discovery и документации | средний | workaround: version-pinned список семи IDs |
| 3 | Benign gRPC набирал OWASP score 16–21 | несовместимость generic CRS с HTTP/2/protobuf | высокий | узкие gRPC exclusions, regression пройден |
| 4 | OWASP `920280` даёт известный FP на HTTP/2 | известная платформой несовместимость | высокий при threshold 5 | правило отключено глобально |
| 5 | FULL mode отправляет машинных клиентов на CAPTCHA | ловушка маршрутизации | высокий | API-mode правила стоят раньше catch-all |
| 6 | Dry-run не завершает обработку security rules | ожидаемая семантика, опасная ловушка | высокий при default `DENY` | default `ALLOW`, единый переключатель dry-run |
| 7 | HTTP catch-all мог перехватить gRPC | интеграционная ошибка ALB, не баг SWS | средний | gRPC routes, backend, health check и SG настроены |
| 8 | Первые body-limit тесты блокировались правилом `920420` | ошибка тестовой методики | средний | повторено с допустимым form content type |
| 9 | Для over-limit лог показывает body size ровно 8192 | ограничение наблюдаемости | низкий/средний | исходный размер хранится в test report/marker |
| 10 | Status-only классификация путала WAF и origin | ошибка тестовой методики | высокий для качества отчёта | origin marker + SWS-log correlation |
| 11 | Корреляция по времени/request ID была ненадёжной | ограничение наблюдаемости/интеграции | средний | отдельный `X-WAF-Test-ID`, parser fallback |
| 12 | Схема экспортированных логов имела варианты | совместимость анализатора | средний | `swslog` нормализует обе схемы и dry-run отдельно |
| 13 | Оба rule set дали FP и signature misses | качество конкретных наборов правил | высокий для реального приложения | задокументировано; требуется узкий dry-run tune |
| 14 | Retention 72h короче рекомендуемой недели OWASP dry-run | операционный долг | средний | открыто для production |
| 15 | Raw WAF logs содержат чувствительные значения | privacy/security risk | высокий при небрежном экспорте | в Git только санитизированные агрегаты |

Уровень риска здесь относится к потенциальному влиянию на доступность или
качество защиты, а не является CVSS-оценкой. На лабораторном стенде инцидента с
пользовательскими данными не было.

Доказательная база разделена на два уровня:

- финальные A/B результаты воспроизводимы по санитизированным HTTP/SWS
  артефактам в `reports/2026-08-28`;
- диагностические события до тюнинга (zero-group Yandex profile, исходные gRPC
  FP и первые body probes) были повторно проверены в raw Cloud Logging, но сами
  raw записи намеренно не сохранены в Git из-за чувствительных значений и
  retention 72 часа.

## 1. Yandex Ruleset без групп фактически не защищал

**Классификация:** подтверждённая fail-open ловушка конфигурации; кандидат на
дефект семантической валидации API/provider. Это не подтверждённый Яндексом баг,
поэтому в отчёте не утверждается, что у него есть официальный defect ID.

### Симптом

Был создан WAF-профиль Yandex Ruleset 0.1.1, в котором descriptor возвращал 129
правил, а каждое правило было `is_enabled = true`. Настройки `ya_rule_set` при
этом не содержали ни одного `rule_group`.

Профиль успешно принялся API. Контрольные XSS, SQLi, LFI и RCE запросы прошли:

- итоговое действие `ALLOW`;
- WAF score `0`;
- `waf_matched_rules` пуст;
- origin-маркер подтвердил, что запрос действительно дошёл до приложения.

То есть это не был высокий threshold или dry-run: сигнатуры вообще не дали
событий. Сам факт наличия профиля и 129 включённых правил создавал ложное
ощущение защиты.

### Причина

В Yandex Ruleset решение по anomaly score задаётся на уровне групп. Одного
перечня включённых сигнатур недостаточно: профилю нужны явные `rule_group` с
действием и порогом. API/provider не отвергли семантически пустую
конфигурацию и не выдали предупреждение.

### Исправление

В Terraform явно заданы все семь групп версии 0.1.1 с threshold 7:

```text
yars-v0.1.1-attack-cve
yars-v0.1.1-attack-lfi
yars-v0.1.1-attack-rce
yars-v0.1.1-attack-rfi
yars-v0.1.1-attack-sqli
yars-v0.1.1-attack-tool
yars-v0.1.1-attack-xss
```

В ресурсе добавлена precondition: набор ключей должен в точности совпадать со
всеми семью группами. Исключение разрешено только при
`yandex_ruleset_direct_blocking = true`, который предназначен для
контролируемого discovery, а не для production.

Отрицательная проверка с map из одной группы теперь останавливает
`terraform plan` сообщением:

```text
Yandex Ruleset needs explicit settings for all seven 0.1.1 groups unless
direct blocking is enabled for discovery.
```

После добавления групп та же 37-case матрица дала 17/23 детекта атак, а все
37 запросов были сопоставлены с логами без missing/conflict/inconclusive.

### Как не допустить повторения

- Не считать число `enabled rules` проверкой работоспособности профиля.
- После каждого создания/смены rule set выполнять canary: benign должен дойти
  до origin, гарантированно распознаваемый XSS должен дать dry-run match или
  active deny.
- Проверять наличие каждой ожидаемой группы на plan-time.
- При обновлении версии не переносить opaque group IDs автоматически: сначала
  получить каталог новой версии и повторить regression.
- Никогда не включать Yandex Ruleset напрямую в enforcement до такого canary.

## 2. Descriptor и Terraform provider не дают полного discovery групп

**Классификация:** пробел API/provider ergonomics и документации; не runtime-баг
WAF.

Data source `yandex_sws_waf_rule_set_descriptor` позволяет найти набор по
display name/version и перечисляет сигнатуры, но в используемой схеме не
экспортирует каталог `rule_group` с их opaque IDs. В документации ресурса блок
`ya_rule_set.rule_group` описан, однако сами допустимые group IDs не
перечислены, а описания некоторых полей недостаточно специфичны.

Дополнительно create API ожидал внутренний идентификатор набора
`YARS_0_1_1`/`OWASP_CRS_4_0_0`, а не display-представление descriptor. Точный
первоначальный RPC error не был сохранён, поэтому здесь фиксируется только
наблюдавшийся контракт, без реконструкции текста ошибки.

Workaround в репозитории:

- display name и version используются для чтения descriptor;
- внутренний enum и семь group IDs явно закреплены рядом с версией;
- precondition не даёт молча потерять группу;
- смена версии рассматривается как migration, а не обычный bump строки.

Остаточный риск: новые версии могут изменить enum, набор групп или IDs. Это
нужно обнаруживать в отдельном dry-run до обновления production.

Ссылки на использованную версию документации provider:

- [ресурс `yandex_sws_waf_profile`](https://github.com/yandex-cloud/terraform-provider-yandex/blob/v0.220.0/docs/resources/sws_waf_profile.md);
- [data source descriptor](https://github.com/yandex-cloud/terraform-provider-yandex/blob/v0.220.0/docs/data-sources/sws_waf_rule_set_descriptor.md).

## 3. OWASP CRS блокировал нормальный gRPC как нарушение протокола

**Классификация:** подтверждённый false positive из-за несовместимости generic
HTTP rule set с HTTP/2/protobuf framing.

### Симптом и доказательство

До тюнинга обычные gRPC health, Ping, Echo и Watch запросы в dry-run набирали
score от 16 до 21 при целевом threshold 5. Срабатывали:

| CRS ID | Смысл правила | Score в наблюдениях |
|---:|---|---:|
| `920180` | POST без ожидаемого `Content-Length`/`Transfer-Encoding` | 3 |
| `920280` | отсутствует Host header | 3 |
| `920420` | content type не разрешён policy | 5 |
| `920270` | null byte в request | 5 |
| `921150` | CR/LF интерпретирован как header injection | 5 |

Для HTTP/2 часть HTTP/1.1-предположений неприменима, а protobuf — бинарный
формат, в котором `NUL`, CR и LF могут быть обычными байтами. При threshold 5
enforcement заблокировал бы нормальную работу gRPC.

Имена и логика правил сверялись с исходниками OWASP CRS 4.0.0:

- [REQUEST-920-PROTOCOL-ENFORCEMENT.conf](https://github.com/coreruleset/coreruleset/blob/v4.0.0/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf);
- [REQUEST-921-PROTOCOL-ATTACK.conf](https://github.com/coreruleset/coreruleset/blob/v4.0.0/rules/REQUEST-921-PROTOCOL-ATTACK.conf).

Yandex Cloud отдельно документирует известный false positive правила `920280`
при HTTP/2 в [рекомендациях по WAF](https://yandex.cloud/ru/docs/smartwebsecurity/concepts/waf#recommendations).

### Исправление и regression

- `920280` отключено глобально, поскольку это известный HTTP/2 FP.
- `920180`, `920270`, `920280`, `920420`, `921150` исключены только при
  `Content-Type` с prefix `application/grpc`.
- `log_excluded = true`, чтобы применение exception оставалось наблюдаемым.

После изменения четыре benign gRPC-вызова получили score 0. XSS Echo сохранил
правила `941100`, `941110`, `941160`, score 15 и был остановлен с gRPC
`PermissionDenied`/HTTP 403. То есть exception не отключил весь WAF и не убрал
XSS-сигнатуры.

### Остаточный риск

SWS/CRS не декодирует protobuf по `.proto`. Защита содержимого gRPC остаётся
эвристической и не заменяет authentication, authorization, schema validation,
лимиты размера/частоты и защиту streaming. Условие exception сейчас основано на
`Content-Type`; при более сложной конфигурации его стоит дополнительно сузить
host/service/path, если API профиля позволяет нужное пересечение условий.

## 4. API/FULL, CAPTCHA и порядок правил легко ломают машинных клиентов

**Классификация:** ожидаемая семантика SWS и интеграционная ловушка, не баг.

Правила security profile проверяются по priority. Для браузерного catch-all
используется FULL, который может вернуть CAPTCHA `302`. Это корректно для
браузера, но ломает health checks, REST-клиентов и gRPC, которые не умеют
проходить CAPTCHA.

Рабочий порядок:

1. `/healthz` — API mode;
2. `/readyz` — API mode;
3. `Content-Type: application/grpc...` — API mode;
4. `/api...` — API mode;
5. catch-all — FULL mode.

Контрольный browser-like `curl /` получил CAPTCHA 302, а health/API/gRPC — нет.
Это ожидаемый результат, а не false positive WAF.

Отдельная тонкость: prefix `/api` также совпадёт с `/apiary`. Если это не
нужно, условие следует разбить на exact `/api` и prefix `/api/`.

Официальная семантика priorities и действий описана в
[документации правил SWS](https://yandex.cloud/ru/docs/smartwebsecurity/concepts/rules).

## 5. Dry-run не означает «это правило остановило обработку»

**Классификация:** ожидаемое, но опасное для rollout поведение.

Dry-run правило пишет потенциальное решение, но не влияет на трафик; после него
может сработать следующее активное правило или `default_action`. Поэтому
конфигурация «WAF в dry-run + default DENY» способна блокировать весь трафик,
хотя оператор ожидает только логирование.

В текущей конфигурации:

- все пять WAF routes управляются одним `sws_dry_run`;
- `default_action = ALLOW`;
- перед enforcement проверяются не только dry-run verdict, но и фактическое
  active action;
- анализатор хранит active и dry-run evaluations раздельно, даже если они
  пришли в одном raw record.

Такое поведение подтверждено в
[руководстве по базовой настройке SWS](https://yandex.cloud/ru/docs/smartwebsecurity/tutorials/sws-basic-protection).

## 6. Для native gRPC недостаточно добавить одно правило WAF

**Классификация:** пробел исходной ALB-интеграции, не баг SWS.

Первоначальная схема была HTTP-only. Чтобы честно проверить gRPC через тот же
SWS profile, понадобилась вся цепочка:

- gRPC server на backend port 9090;
- отдельный `grpc_backend` и gRPC health check по
  `sws.lab.v1.LabService`;
- маршруты `/sws.lab.v1.LabService/` и `/grpc.`;
- размещение gRPC routes до HTTP prefix `/` catch-all;
- ingress 9090 от security group ALB к backend;
- проверка здоровья targets в обеих зонах.

Если пропустить любой элемент, ошибка выглядит как проблема WAF: timeout,
unhealthy backend, 404/405 или отсутствие нужного WAF-события. Поэтому
диагностика должна идти по цепочке client → listener → route → SWS → backend
group → health check → origin journal.

После настройки оба gRPC target были `HEALTHY`; benign вызовы дошли до origin,
а блокированный XSS Echo в origin journal отсутствовал.

## 7. Первые тесты границы body size измеряли не то

**Классификация:** исправленная ошибка тестовой методики.

### Что произошло

Первые generated-body тесты отправляли raw/text payload. Все размеры от 1000
до 8192 bytes блокировались. На первый взгляд это выглядело как неверная граница
`size_limit`.

Логи показали другую причину:

- даже пятибайтовое `hello` получило `920420` — content type запрещён policy;
- многие raw payload дополнительно получили `921150`;
- у этих блокировок были WAF rule IDs и anomaly score, то есть это не действие
  body-size policy.

### Как тест исправлен

Граница была повторена с допустимым `application/x-www-form-urlencoded` и
без attack-like содержимого:

- 7000, 7800, 7900, 7999, 8000, 8001, 8191 и 8192 bytes — `ALLOW`, WAF rules
  отсутствуют;
- 8193, 8250, 9000 и 16384 bytes — `DENY`, WAF rules отсутствуют.

Таким образом фактическая граница — ровно 8 KiB. `DENY` выше неё создаёт
`analyze_request_body.size_limit_action`, а не сигнатура rule set. Финальная
матрица поэтому относит эти кейсы к `platform-policy`, а не к attack coverage.

### Вывод для будущих тестов

При проверке одного ограничения все прочие параметры должны быть валидными:
метод, content type, encoding и содержимое. Иначе content-type/protocol rule
получит приоритет и результат нельзя приписать size limit.

## 8. Лог over-limit запроса не показывает исходный размер тела

**Классификация:** подтверждённое ограничение наблюдаемости.

Для всех запросов выше лимита поле `http_body_size` в SWS log было равно 8192,
включая тела 8193, 8250, 9000 и 16384 bytes. По нему нельзя восстановить
исходный размер: оно отражает объём, доступный анализу/достигший cap.

Workaround:

- ожидаемый размер хранит `wafcheck` report;
- `X-WAF-Test-ID` однозначно связывает report и log;
- метрика `denied_without_waf_match` учитывается отдельно;
- raw payload для доказательства размера не сохраняется.

Для production мониторинга такой `DENY` следует классифицировать по отсутствию
matched WAF rules и известной body policy, а не пытаться вычислять реальный
размер по `http_body_size`.

Сам лимит 8 KiB и выбранное действие DENY — не баг. Это осознанная политика
стенда. Реальный upload endpoint требует отдельного маршрута/профиля; переход на
IGNORE означает, что остаток тела не будет проверен сигнатурами.

## 9. Код ответа сам по себе не доказывает решение WAF

**Классификация:** исправленная ошибка тестового клиента и отчётности.

Найдены пять неоднозначных случаев:

- edge deny возвращал `403` без origin-маркера;
- FULL CAPTCHA возвращала `302`;
- Yandex Ruleset пропустил TRACE, а origin корректно вернул `405`;
- пропущенный PHPunit path дошёл до origin и получил обычный `404`;
- специальный endpoint origin намеренно возвращал `418`.

Наивный тест «любые 4xx/5xx означают block» ошибочно засчитал бы `404`, `405`
и `418` как детекты WAF. Следование redirect также могло бы скрыть CAPTCHA.

Исправленный `wafcheck`:

1. не следует redirect;
2. сначала распознаёт CAPTCHA header/status;
3. затем явные block statuses;
4. затем доверенный lab origin marker `X-Lab-Response`;
5. оставшиеся 2xx считает allow, а неоднозначные ответы — unknown;
6. подтверждает результат отдельным SWS log.

Origin marker — лабораторный механизм, а не универсальное доказательство для
production. Там нужен request ID и корреляция edge/origin logs.

## 10. Корреляция логов: часы и обычный request ID подвели

**Классификация:** интеграционная/операционная проблема наблюдаемости.

### Наблюдения

- В финальном сравнении timestamp клиента и SWS отличались примерно на
  4 минуты 37 секунд.
- Причина skew не доказана; его нельзя корректно называть багом SWS. Это могло
  быть расхождение локальных часов, timestamp на другом этапе тракта или их
  комбинация.
- Поиск только по временному окну захватывал фоновые `/api/stats` и создавал
  впечатление, что тестовые записи отсутствуют.
- ALB request ID не обязан совпадать с присланным клиентом `X-Request-ID`.
- `yc logging read` без явного `--until` может продолжать ждать новые записи,
  что выглядит как зависшая диагностическая команда; ограничение окна
  предусмотрено в [справке CLI](https://yandex.cloud/ru/docs/cli/cli-ref/logging/cli-ref/read).

### Исправление

Каждый тест получает отдельный `X-WAF-Test-ID` вида
`<run-id>-<ordinal>-<case>`. Он сохраняется в SWS headers и имеет приоритет при
корреляции; затем анализатор пробует ALB ID и `X-Request-ID`.

Финальные результаты:

- OWASP: `37/37` logs, 0 missing, 0 conflicts, 0 inconclusive;
- Yandex: `37/37` logs, 0 missing, 0 conflicts, 0 inconclusive.

Для ограниченной выгрузки нужно указывать и начало, и конец окна, а фильтрацию
делать по marker, а не только по времени.

## 11. Формат SWS log потребовал терпимого нормализатора

**Классификация:** schema compatibility issue в инструменте, не доказанный баг
Cloud Logging.

Экспорты встречались в нескольких формах:

- JSON array и JSONL;
- wrapper objects (`entries`, `records`, `items`, `logs`);
- плоские `labels.action` и вложенные `smartwebsecurity.*`;
- headers как `{key, value}`; некоторые внешние/тестовые представления используют
  `{name, value}`;
- active и `dry_run_*` verdicts в одной исходной записи.

Первый вариант парсера, ожидающий одно имя поля header/request ID, мог не найти
маркер и дать ложный `missing`. `swslog` теперь нормализует варианты, создаёт
отдельные active/dry-run evaluations и сообщает `missing`, `conflict` и
`inconclusive` раздельно.

Канонические поля сверялись с
[официальной схемой логов SWS](https://yandex.cloud/ru/docs/smartwebsecurity/concepts/logging).

## 12. Реальные false positive и пропуски сигнатур

**Классификация:** ограничения покрытия конкретных версий rule set. Это не
доказательство сбоя самой SWS-платформы.

### OWASP CRS 4.0.0, PL1, threshold 5

- `benign-json-code` был заблокирован со score 10 правилами `942100` и
  `942230` (SQLi false positive).
- `rce-query-semicolon` (`hello; id`) прошёл со score 0.
- `cve-spring-classloader` прошёл со score 0.
- Итого: 21/23 attacks detected, 1/11 benign false positive.

Глобально поднимать threshold выше 10 нельзя: несколько полезных детектов имеют
score только 5 или 10. Нужен узкий exception для подтверждённого JSON field/path
и правил `942100`/`942230`, затем полный dry-run regression.

### Yandex Ruleset 0.1.1, все группы, threshold 7

- `benign-sql-words` был заблокирован со score 10 правилом SQLI
  `yars-v0.1.1-id8020220-attack-sqli`.
- Не обнаружены RFI URL, два RCE-варианта, TRACE, PHPunit path и Bitrix redirect;
  все шесть имели score 0 и пустой список rules.
- Spring classloader, пропущенный OWASP, Yandex обнаружил со score 10.
- Итого: 17/23 attacks detected, 1/11 benign false positive.

Три SQLi probes Yandex набрали 23, 28 и 30. Поэтому SQLI threshold 11 — разумная
гипотеза для следующего dry-run, но не production-настройка. При score 0
изменение threshold не помогает: нужна другая сигнатура, новая версия набора
или application-level защита.

Полная методика, case-level различия и ограничения выборки находятся в
[отчёте сравнения](YANDEX_RULESET_COMPARISON_2026-08-28.md).

## 13. Retention недостаточен для рекомендованного dry-run

**Классификация:** открытый операционный долг.

Текущая log group хранит записи 72 часа, тогда как Yandex Cloud рекомендует
наблюдать OWASP в dry-run не менее недели. За 72 часа можно проверить
техническую корректность, но нельзя охватить недельные batch jobs, выходные и
редкие бизнес-сценарии.

Перед production rollout нужно:

- увеличить retention как минимум до полного окна калибровки либо экспортировать
  безопасные агрегаты;
- оставить `discard_allow_percentage = 0` на период tune, иначе нельзя оценить
  долю FP и пропущенные записи;
- после enforcement определить sampling/retention уже по стоимости, privacy и
  требованиям расследований;
- перезапускать окно наблюдения после изменения threshold, rules или exclusions.

## 14. Raw WAF logs содержат чувствительные данные

**Классификация:** ожидаемый security/privacy риск журналирования.

В raw событиях могут быть client IP, query/header values и фрагмент,
сопоставившийся с сигнатурой (`matched_data_value`). Поэтому сохранение полного
экспорта в Git создало бы отдельную утечку даже при корректной работе WAF.

Принятые меры:

- raw Cloud Logging exports не коммитятся;
- клиентские адреса маскируются до IPv4 `/24` и IPv6 `/48` либо полностью
  исключаются;
- query values, body и `matched_data_value` отбрасываются;
- артефакты содержат только case ID, action, score, rule/group IDs и безопасные
  агрегаты;
- полный IP можно включить в `swslog` только явным флагом.

Официальная настройка экспорта описана в
[инструкции по логированию](https://yandex.cloud/ru/docs/smartwebsecurity/operations/configure-logging).

## Что не является багом

Чтобы не повторять ложную диагностику:

- **8193-byte body → DENY без rule ID** — ожидаемая body-size policy.
- **FULL → CAPTCHA 302** — ожидаемый browser challenge.
- **Dry-run не блокирует** — его назначение состоит в логировании потенциального
  решения; итог задаёт следующая active rule/default action.
- **Attack marker со score 0** — пробел сигнатур конкретного rule set, а не
  доказательство отказа SWS.
- **Origin 404/405/418** — решение приложения, если запрос имеет origin marker и
  SWS action ALLOW.
- **OWASP не понимает protobuf schema** — архитектурное ограничение generic WAF.
- **8 KiB недостаточно для upload** — несовместимость выбранной политики с
  требованиями endpoint, а не ошибка применения правила.
- **Расхождение timestamp 4:37** — наблюдение с неустановленной причиной; данных
  недостаточно, чтобы возложить его на SWS.

## Что было исправлено в репозитории

- WAF переведён из dry-run в enforcement после regression.
- OWASP threshold снижен до 5 только после тюнинга.
- Добавлены узкие gRPC exclusions и логирование исключений.
- API/FULL routes упорядочены до browser catch-all.
- Добавлена полная gRPC ALB/backend/health-check/SG цепочка.
- Body boundary test очищен от content-type срабатываний.
- `wafcheck` различает edge, CAPTCHA, origin и unknown.
- `swslog` нормализует варианты схемы и коррелирует по `X-WAF-Test-ID`.
- Yandex Ruleset получил все семь групп и fail-closed Terraform precondition.
- Финальные отчёты не содержат raw payload и полных client IP.

## Открытые действия

| Приоритет | Действие | Условие готовности |
|---|---|---|
| P1 | Увеличить retention для production dry-run | доступно не менее полного недельного цикла |
| P1 | Устранить OWASP JSON FP узким exception | benign JSON allow; вся attack regression без деградации |
| P1 | Добавить alert на WAF profile без canary detection | смена профиля не проходит rollout при score 0 на известном probe |
| P2 | Проверить Yandex SQLI threshold 11 только в dry-run | расширенный benign/SQLi corpus и реальный трафик без новых misses |
| P2 | Протестировать OWASP CRS 4.8.0 отдельно | та же фиксированная матрица и сопоставимые логи |
| P2 | Уточнить gRPC exception host/service/path | исключение минимально для фактической топологии |
| P2 | Разделить exact `/api` и prefix `/api/` при появлении соседних путей | `/apiary` не получает API policy случайно |
| P3 | Передать vendor feedback по zero-group profile/discovery | API валидирует effective policy или явно предупреждает |

## Предложения для API/provider SWS

Эти пункты — инженерные предложения по результатам стенда, а не ссылки на
зарегистрированные vendor bugs:

1. Отклонять Yandex WAF profile с включёнными rules, но без effective
   `rule_group`, либо возвращать явное предупреждение.
2. Возвращать каталог групп, их IDs и рекомендуемые thresholds через rule set
   descriptor.
3. Использовать один идентификатор rule set для discovery и create либо явно
   публиковать mapping display descriptor → internal enum.
4. Добавить в Terraform docs реальные описания полей `rule_group` и полный
   пример с семью группами.
5. В body-limit log различать `inspected_body_size` и исходный
   `request_body_size`, если это возможно без избыточного раскрытия данных.
6. Дать отдельный официальный профиль рекомендаций для gRPC/HTTP/2 и protobuf,
   включая безопасную область исключений.

## Воспроизведение и проверка

Финальная HTTP-матрица:

```bash
cd /home/ruslan/src/ycl-sws-test/misc
go run ./wafcheck \
  -plan examples/sws-lab-ruleset-comparison.json \
  -target https://sws.grauwolf32.tech \
  -run-id regression-$(date -u +%Y%m%dT%H%M%SZ) \
  -parallel 1 \
  -output waf-report.json
```

Корреляция с ограниченной выгрузкой логов:

```bash
SWS_LOG_FROM='YYYY-MM-DDThh:mm:ssZ'
SWS_LOG_UNTIL='YYYY-MM-DDThh:mm:ssZ'

yc logging read \
  --group-id <log-group-id> \
  --since "$SWS_LOG_FROM" \
  --until "$SWS_LOG_UNTIL" \
  --limit 1000 \
  --format json \
| go run ./swslog \
    -input - \
    -report waf-report.json \
    -request-id-prefix regression- \
    -fail-on-empty \
    -fail-on-missing \
    -fail-on-conflict \
    -fail-on-inconclusive
```

Перед активным прогоном следует убедиться, что target принадлежит команде и
окно тестирования согласовано. Команда выше использует только инертные markers;
origin ничего не исполняет.

## Связанные материалы

- [итоговая проверка enforcement](WAF_VALIDATION_2026-08-28.md);
- [гайд по настройке и тюнингу](SWS_TUNING_GUIDE.md);
- [сравнение OWASP и Yandex Ruleset](YANDEX_RULESET_COMPARISON_2026-08-28.md);
- [описание `wafcheck` и `swslog`](misc/README.md);
- [санитизированные артефакты](reports/2026-08-28/README.md);
- [официальное описание WAF](https://yandex.cloud/ru/docs/smartwebsecurity/concepts/waf);
- [официальная настройка rule sets](https://yandex.cloud/ru/docs/smartwebsecurity/operations/configure-set-rules).
