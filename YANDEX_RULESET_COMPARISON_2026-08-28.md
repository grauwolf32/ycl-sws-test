# Yandex Ruleset 0.1.1 vs OWASP CRS 4.0.0 в SWS

## Итог

Для текущего приложения и фиксированной матрицы лучше показал себя действующий
OWASP CRS 4.0.0: он заблокировал `21/23` атак (`91.3%`), Yandex Ruleset 0.1.1 —
`17/23` (`73.9%`). Разница — четыре атаки, или `−17.4` процентного пункта для
Yandex Ruleset. Оба набора дали по одному false positive на `11` легитимных
запросах (`9.1%`), но на разных данных.

Рекомендация: оставить OWASP CRS 4.0.0 активным. Yandex Ruleset пока использовать
только в dry-run/canary, проверить SQLI-порог `11` и повторить тест на будущей
версии. Это вывод по данному стенду, а не универсальный benchmark продуктов.

После сравнения профиль возвращён в рабочее состояние:

- active rule set: `OWASP_CRS`;
- WAF profile: `fevmrn97327rctdd4sme`;
- security profile: `fevkqrqgh8l7naetijqh`;
- enforcement: `dry_run = false`;
- контрольный XSS блокируется `403`, benign health доходит до origin;
- оба созданных WAF-профиля остаются в Terraform для повторяемого A/B-теста.

## Что именно сравнивалось

Smart Web Security — платформа, в которой работают оба набора. Здесь
сравниваются два управляемых signature rule set внутри одного SWS-профиля, а не
«Yandex Ruleset против SWS» целиком.

| Параметр | OWASP | Yandex |
|---|---|---|
| Набор | OWASP Core Ruleset `4.0.0` | Yandex Ruleset `0.1.1` |
| Правила | PL1; `920280` отключено | все 129 правил включены |
| Порог | общий `5` | `7` отдельно для всех 7 групп |
| Direct-blocking | нет | нет |
| Группы | определяются CRS | CVE, LFI, RCE, RFI, SQLI, Tool, XSS |
| SWS routing | одинаковый API/FULL | одинаковый API/FULL |
| Body policy | `8 KiB`, over-limit `DENY` | та же |
| Логи | 100% ALLOW/DENY/CAPTCHA | те же |

Yandex Cloud указывает, что Yandex Ruleset 0.1.1 содержит 129 правил, включая 34
новых правила для критичных CVE, и относит наборы Яндекса к Preview. OWASP CRS и
Yandex Ruleset имеют разную модель порогов, поэтому их score нельзя сравнивать
как единую шкалу. Источник: [профили WAF в документации Yandex Cloud](https://yandex.cloud/ru/docs/smartwebsecurity/concepts/waf).

## Методика

Использована одна JSON-матрица и один клиент `wafcheck`:

- 6 обычных benign-кейсов;
- 5 benign-edge-кейсов: естественный HTML/SQL/shell-подобный текст, апострофы,
  JSON с фрагментом кода;
- 23 безопасных инертных attack marker: XSS, SQLi, LFI, RFI, RCE, scanners,
  TRACE, CVE и composite;
- 3 проверки платформенной политики тела: `7900`, `8192`, `8193` байта.

Все payload обрабатываются лабораторным origin как текст и ничего не исполняют.
Запросы шли последовательно с одинаковыми route/body/content-type. Redirects
были выключены; блок определялся по edge `403`, allow — по origin-маркеру
`X-Lab-Response`. Origin `404/405` не считался блоком WAF.

Run ID:

- `cmp-owasp-20260828-final`;
- `cmp-yars-20260828-final`.

Каждый из `74` запросов сопоставлен с SWS-логом по `X-WAF-Test-ID`: `37/37` для
каждого профиля, `0` missing, `0` conflicts, `0` inconclusive. Клиентские часы
отставали от timestamp SWS примерно на 4 минуты 37 секунд, что дополнительно
подтвердило необходимость marker-based, а не time-only корреляции.

## Результаты

| Метрика | OWASP 4.0.0 | Yandex 0.1.1 | Разница Yandex |
|---|---:|---:|---:|
| Заблокировано атак | `21/23` (`91.3%`) | `17/23` (`73.9%`) | `−4`, `−17.4 п.п.` |
| Пропущено атак | `2/23` | `6/23` | `+4` |
| False positive на benign | `1/11` (`9.1%`) | `1/11` (`9.1%`) | одинаково |
| Проверки body policy | `3/3` | `3/3` | одинаково |
| Все ожидания матрицы | `34/37` (`91.9%`) | `30/37` (`81.1%`) | `−4` |
| Корреляция HTTP ↔ SWS | `37/37` | `37/37` | одинаково |
| Сработавшие сигнатуры | `52` | `63` | score/rules неэквивалентны |

### Покрытие по семействам

| Семейство | OWASP | Yandex |
|---|---:|---:|
| XSS | `3/3` | `3/3` |
| SQLi | `3/3` | `3/3` |
| LFI | `3/3` | `3/3` |
| RFI | `2/2` | `1/2` |
| RCE | `3/4` | `2/4` |
| Tool/method | `3/3` | `2/3` |
| CVE markers | `3/4` | `2/4` |
| Composite | `1/1` | `1/1` |

Оба набора полностью закрыли XSS, SQLi, LFI и composite в этой матрице.
Разница появилась в RFI, RCE, method enforcement и CVE-маркерах.

### Различия по кейсам

OWASP заблокировал, а Yandex пропустил:

- `rfi-query-http` — внешний URL в include-подобном query;
- `rce-query-subshell` — `$(id)`;
- `tool-trace-method` — `TRACE` дошёл до origin и получил application `405`;
- `cve-phpunit-path` — запрос дошёл до origin и получил application `404`;
- `cve-bitrix-redirect` — маркер open redirect дошёл до origin.

Yandex заблокировал, а OWASP пропустил:

- `cve-spring-classloader` — Spring classloader marker, score `10`, группа CVE.

Оба пропустили слабый `rce-query-semicolon` (`hello; id`). Все шесть пропусков
Yandex и оба пропуска OWASP имели score `0` и пустой `waf_matched_rules`.
Следовательно, снижение anomaly threshold эти пропуски не исправит.

### False positive

OWASP заблокировал benign JSON с фрагментом `if (a < b) return true;`:

- итоговый score `10`;
- правила `942100` и `942230`, группа SQLi.

Yandex этот JSON разрешил, но заблокировал естественную фразу с SQL-словами
`select`, `union`, `update`:

- итоговый score `10`;
- правило `yars-v0.1.1-id8020220-attack-sqli`;
- группа `yars-v0.1.1-attack-sqli`, порог `7`.

Три контрольных SQLi у Yandex набрали `23`, `28`, `30`. Поэтому отдельный SQLI-
порог `11` — обоснованный кандидат для следующего dry-run: в этой матрице он
убирает FP, не теряя эти три детекта. Это ещё не production-рекомендация: нужна
выборка реального трафика и более широкий attack regression.

Для OWASP глобально поднять threshold выше `10` нельзя без существенной потери
покрытия: несколько подтверждённых атак в матрице набрали только `5` или `10`.
Корректный путь — узкое exception для конкретных правил и конкретного JSON-поля
на подтверждённом маршруте, с `log_excluded` и новым dry-run.

### Body policy

Оба профиля разрешили form body `7900` и ровно `8192` байта и заблокировали
`8193`. Over-limit запись имела `DENY`, но не содержала WAF-сигнатуры — это
ожидаемое решение `analyze_request_body.size_limit_action`, а не детект rule set.
Поэтому этот кейс не включён в 23 атаки.

### Задержка запроса

| Наблюдение, один последовательный прогон | OWASP | Yandex |
|---|---:|---:|
| Mean | `16.848 ms` | `18.400 ms` |
| Median | `14.513 ms` | `16.064 ms` |
| p95 | `33.716 ms` | `30.523 ms` |
| Max | `53.169 ms` | `64.617 ms` |

Это не latency benchmark: по одному запросу на кейс, без warm-up, рандомизации
порядка и измерения origin/network baseline. По этим данным нельзя утверждать,
что один rule set быстрее другого.

## Анализ журналов

| Показатель | OWASP | Yandex |
|---|---:|---:|
| SWS events | `37` | `37` |
| `ALLOW` | `14` | `18` |
| `DENY` | `23` | `19` |
| WAF matches | `52` | `63` |
| Max score | `50` | `83` |
| Allow с WAF match | `0` | `0` |
| Deny без WAF match | `1` | `1` |

Единственный `DENY` без matched rule у каждого набора — ожидаемый body over-limit.
У всех signature-deny есть rule IDs. В логах не найдено решений, конфликтующих
с наблюдавшимся HTTP-ответом.

После возврата OWASP дополнительно проанализировано нетестовое окно
`22:50:00–22:57:00 UTC`: 84 запроса `GET /api/stats`, все `ALLOW`, score `0`,
без WAF matches, `DENY` или `CAPTCHA`. Полные IP и raw payload не сохранялись.

Отдельный обнаруженный риск конфигурации: API принял Yandex WAF-профиль с
включёнными правилами, но без настроенных `rule_group`; контрольные XSS/SQLi/LFI/
RCE тогда прошли с score `0`. После включения всех семи групп с порогом `7`
детекты заработали. Terraform теперь отклоняет map, в котором отсутствует хотя
бы один из семи ожидаемых group ID.

## Ограничения вывода

- всего 23 attack и 11 benign-кейсов, один источник и один последовательный
  прогон на семейство;
- используются минимальные инертные markers, а не corpus реальных exploit/
  evasions; нет double encoding, fragmentation и большого набора bypass'ов;
- тестируется лабораторное приложение, а не production-распределение полей;
- latency и устойчивость под нагрузкой не тестировались;
- сравнивались конкретно OWASP `4.0.0` и Yandex `0.1.1`; документация уже
  перечисляет OWASP `4.8.0`, который требует отдельной regression-проверки;
- Yandex Ruleset находится в Preview, его следующие версии могут изменить
  покрытие и false-positive profile.

## Решение и следующие шаги

1. Оставить `OWASP_CRS`, PL1, threshold `5` в enforcement — выполнено.
2. Для реального JSON endpoint'а локализовать OWASP FP до поля и проверить узкое
   исключение правил `942100/942230` в dry-run; не отключать их глобально.
3. Проверить Yandex SQLI threshold `11` только в dry-run и на расширенном
   SQLi/benign corpus.
4. Добавить regression-кейсы для пяти преимуществ OWASP и Spring-преимущества
   Yandex, чтобы будущие версии сравнивались на том же baseline.
5. Отдельно протестировать доступный OWASP CRS `4.8.0` против текущего `4.0.0`.
6. Повторять A/B после обновления rule set и регулярно анализировать production-
   логи; Yandex Cloud рекомендует включать dry-run при каждом изменении правил
   ([официальная инструкция](https://yandex.cloud/ru/docs/smartwebsecurity/operations/configure-set-rules)).

## Артефакты и воспроизведение

- матрица: [`misc/examples/sws-lab-ruleset-comparison.json`](misc/examples/sws-lab-ruleset-comparison.json);
- HTTP OWASP: [`reports/2026-08-28/owasp-http.json`](reports/2026-08-28/owasp-http.json);
- SWS OWASP: [`reports/2026-08-28/owasp-logs.json`](reports/2026-08-28/owasp-logs.json);
- HTTP Yandex: [`reports/2026-08-28/yandex-http.json`](reports/2026-08-28/yandex-http.json);
- SWS Yandex: [`reports/2026-08-28/yandex-logs.json`](reports/2026-08-28/yandex-logs.json);
- post-restore background: [`reports/2026-08-28/post-restore-ambient-logs.json`](reports/2026-08-28/post-restore-ambient-logs.json);
- инструкция по инструментам: [`misc/README.md`](misc/README.md);
- общий WAF validation: [`WAF_VALIDATION_2026-08-28.md`](WAF_VALIDATION_2026-08-28.md).

Команда HTTP-прогона:

```bash
cd /home/ruslan/src/ycl-sws-test/misc
go run ./wafcheck \
  -plan examples/sws-lab-ruleset-comparison.json \
  -target https://sws.grauwolf32.tech \
  -run-id cmp-<ruleset>-<date>-final \
  -parallel 1 \
  -output ../reports/<date>/<ruleset>-http.json
```

Переключение профиля и безопасный rollback описаны в
[SWS_TUNING_GUIDE.md](SWS_TUNING_GUIDE.md).
