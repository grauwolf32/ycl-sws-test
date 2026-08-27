# Артефакты сравнения WAF — 2026-08-28

| Файл | Содержимое |
|---|---|
| `owasp-http.json` | `wafcheck/v1`, 37 HTTP-кейсов с OWASP CRS 4.0.0 |
| `owasp-logs.json` | `swslog/v1`, 37 коррелированных SWS-событий OWASP |
| `yandex-http.json` | `wafcheck/v1`, 37 HTTP-кейсов с Yandex Ruleset 0.1.1 |
| `yandex-logs.json` | `swslog/v1`, 37 коррелированных SWS-событий Yandex |
| `post-restore-ambient-logs.json` | `swslog/v1`, обезличенный нетестовый интервал после возврата OWASP |

Run ID: `cmp-owasp-20260828-final` и `cmp-yars-20260828-final`. Для обоих
прогонов найдено `37/37` логов, без missing/conflict/inconclusive.

Log-анализ содержит только агрегаты, маскированный client `/24`, очищенные paths
без query values и корреляционные case ID. Raw Cloud Logging здесь не сохранён;
`matched_data_value` и request body анализатор намеренно отбрасывает.

Post-restore окно `2026-08-27 22:50:00–22:57:00 UTC`: 84 нетестовых запроса,
все `ALLOW`, score `0`, без WAF matches, `DENY` или `CAPTCHA`.

HTTP-отчёты не содержат body/headers запросов, но содержат URL, включая тестовые
query markers. Это не секреты, однако перед публикацией за пределами команды
файлы всё равно следует просмотреть.

Методика, результаты и ограничения:
[../../YANDEX_RULESET_COMPARISON_2026-08-28.md](../../YANDEX_RULESET_COMPARISON_2026-08-28.md).
