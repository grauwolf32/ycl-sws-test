# Yandex SWS Test Lab

Безопасное Go-приложение-мишень для функциональной проверки Yandex Smart Web Security: WAF, Smart Protection/антибот, правил по URL и ограничений запросов. Оно принимает тестовые маркеры, но не выполняет их, не обращается к базе, shell или файловой системе и не сохраняет пользовательские данные.

> Используйте стенд только в своём или явно согласованном тестовом контуре. Начинайте с единичных запросов и режима логирования, чтобы не затронуть общие лимиты и соседние сервисы.

## Что входит

- веб-интерфейс для ручных WAF-проверок и сравнения browser-like трафика;
- query, form, JSON, multipart и path endpoints;
- детерминированный login `demo/demo`;
- каталог для антибот-сценариев;
- управляемые задержки и коды ответа;
- просмотр безопасного подмножества заголовков, которые видит origin;
- счётчики запросов в памяти и JSON-логи;
- health/readiness endpoints;
- Docker-образ без shell, root и внешних runtime-зависимостей;
- автоматические тесты.

Каждый ответ приложения содержит:

```text
X-Lab-Response: origin
X-Request-ID: lab-...
```

Если заголовка `X-Lab-Response` нет, запрос мог быть остановлен на edge. Подтвердите это по логам SWS и по отсутствию прироста в `/api/stats`: запросы, заблокированные до backend, приложение посчитать не может.

## Быстрый запуск

Требуется Go 1.23 или новее.

```bash
go run -buildvcs=false ./cmd/sws-lab
```

Откройте <http://localhost:8080>. Проверка из терминала:

```bash
curl -i http://localhost:8080/healthz
curl -s http://localhost:8080/api/inspect
```

Сборка бинарного файла:

```bash
make build
./bin/sws-lab
```

Контейнер:

```bash
docker compose up --build
```

В `compose.yaml` порт по умолчанию опубликован только на `127.0.0.1`. Для backend в приватной сети измените публикацию порта под свою схему и ограничьте доступ security groups/сетевыми правилами так, чтобы публичный клиент не мог обойти SWS.

## Подключение к Smart Web Security

Актуально на август 2026 года: профиль безопасности SWS можно подключить к виртуальному хосту Application Load Balancer, API Gateway или защищаемому домену. Для этого стенда типовая схема выглядит так:

```text
тестовый клиент → защищённый host/domain → SWS profile → HTTP backend sws-lab:8080
```

Официальные инструкции:

- [как начать работу с Smart Web Security](https://yandex.cloud/ru/docs/smartwebsecurity/quickstart);
- [как подключить профиль безопасности к ресурсу](https://yandex.cloud/ru/docs/smartwebsecurity/operations/host-connect);
- [понятие профиля безопасности и анализ тела запроса](https://yandex.cloud/ru/docs/smartwebsecurity/concepts/profiles).

Рекомендуемая последовательность:

1. Разверните приложение и сначала проверьте origin напрямую либо с разрешающим профилем.
2. Закройте прямой публичный доступ к backend, чтобы тесты нельзя было провести в обход защищённого host/domain.
3. Создайте профиль безопасности из готового шаблона или с нужными Smart Protection-правилами.
4. Создайте WAF-профиль, выберите нужные наборы правил и добавьте WAF-правило в профиль безопасности.
5. На этапе настройки включите для WAF-правила режим «Только логирование» (dry run), выполните тест-матрицу и проверьте ложные срабатывания.
6. Переведите проверенные правила в режим полной защиты и повторите матрицу.
7. Для API-сценариев учитывайте, что защита не должна рассчитывать на выполнение JavaScript клиентом; для browser-сценария откройте главную страницу настоящим браузером.

Если backend принимает соединения только от доверенного балансировщика/прокси, установите `TRUST_PROXY_HEADERS=true`. Не включайте эту настройку для origin, доступного клиентам напрямую: иначе любой клиент сможет подменить `X-Forwarded-For`.

## Как читать результат

| Наблюдение | Интерпретация |
|---|---|
| `2xx` и `X-Lab-Response: origin` | Запрос дошёл до приложения |
| Ответ edge/CAPTCHA и нет `X-Lab-Response` | Запрос обработан до origin |
| Событие есть в SWS dry-run, но origin ответил `2xx` | Сигнатура сработала только в журналировании |
| Счётчик `/api/stats` не увеличился | Дополнительный признак блокировки до backend |
| `413` и есть `X-Lab-Response` | Лимит тела применило само приложение |
| `4xx/5xx` и есть `X-Lab-Response` | Это симулированный либо валидационный ответ origin |

Промежуточный proxy может удалять пользовательские заголовки. В таком случае сверяйте `X-Request-ID`, JSON-логи приложения и события SWS.

## Тест-матрица WAF

Задайте адрес защищённого хоста:

```bash
export SWS_LAB_TARGET='https://sws-lab.example.com'
```

Сначала baseline:

```bash
curl -i "$SWS_LAB_TARGET/healthz"
curl -i --get --data-urlencode 'value=обычный запрос' "$SWS_LAB_TARGET/api/echo"
curl -i -H 'Content-Type: application/json' \
  --data '{"username":"demo","password":"demo"}' \
  "$SWS_LAB_TARGET/api/login"
```

Затем единичные тестовые маркеры. На origin они безопасно возвращаются как текст; ожидаемое решение о блокировке зависит от настроенного ruleset, порога и режима WAF.

Query/XSS marker:

```bash
curl -i --get \
  --data-urlencode 'value=<script>alert("waf-test")</script>' \
  "$SWS_LAB_TARGET/api/echo"
```

Form/SQL injection marker:

```bash
curl -i -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "comment=' OR '1'='1' --" \
  "$SWS_LAB_TARGET/api/waf/form"
```

JSON/path traversal marker:

```bash
curl -i -H 'Content-Type: application/json' \
  --data '{"path":"../../etc/passwd","action":"waf-test"}' \
  "$SWS_LAB_TARGET/api/waf/json"
```

URI marker:

```bash
curl -i --path-as-is \
  "$SWS_LAB_TARGET/api/waf/path/..%2f..%2fetc%2fpasswd"
```

Command-injection marker:

```bash
curl -i -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'comment=hello; id' \
  "$SWS_LAB_TARGET/api/waf/form"
```

Проверка правила по маршруту:

```bash
curl -i "$SWS_LAB_TARGET/protected/admin"
```

Для multipart используйте только безвредный локальный файл:

```bash
curl -i -F 'document=@README.md;type=text/plain' \
  "$SWS_LAB_TARGET/api/waf/upload"
```

Файл не записывается: приложение вычисляет SHA-256 по потоку и отбрасывает содержимое.

## Проверка антибота

Сначала откройте `$SWS_LAB_TARGET` обычным браузером. Одна сессия создаёт характерную цепочку:

```text
GET / → CSS + JavaScript + favicon → GET /healthz
      → GET /api/catalog → POST /api/antibot/beacon → периодический GET /api/stats
```

Затем сравните с простым клиентом:

```bash
curl -i -A 'sws-lab-check/1.0' "$SWS_LAB_TARGET/api/catalog?page=1&limit=3"
curl -i -A '' "$SWS_LAB_TARGET/api/catalog?page=1&limit=3"
```

Для осторожной серии запросов начните с малого числа и увеличивайте только в пределах согласованного профиля нагрузки:

```bash
for n in $(seq 1 20); do
  curl -sS -o /dev/null -w '%{http_code}\n' \
    "$SWS_LAB_TARGET/api/catalog?page=$n&limit=1"
done
```

Результат антибот-проверки оценивайте по событиям SWS, CAPTCHA/блокировке на клиенте и отсутствию соответствующих запросов в origin-логах. Классификация `by_client_type` в `/api/stats` основана только на User-Agent и является диагностикой стенда, а не собственной антибот-защитой.

## Маршруты

| Метод | Путь | Назначение |
|---|---|---|
| `GET` | `/`, `/assets/*`, `/favicon.svg` | Browser-like загрузка |
| `GET` | `/healthz`, `/readyz` | Health checks |
| `GET` | `/api/inspect` | Origin IP, proxy и разрешённые заголовки |
| `GET` | `/api/stats` | Счётчики в памяти |
| `GET/POST` | `/api/echo` | Query, JSON, form или text body |
| `POST` | `/api/waf/form` | Form WAF markers |
| `POST` | `/api/waf/json` | JSON WAF markers |
| `POST` | `/api/waf/upload` | Multipart, hash-and-discard |
| `GET` | `/api/waf/path/{value}` | URI/path markers |
| `GET` | `/api/catalog`, `/api/catalog/{id}` | Повторяемая bot-цель |
| `POST` | `/api/login` | Baseline и credential-flow |
| `POST` | `/api/antibot/beacon` | Browser event |
| `GET` | `/api/slow?ms=250` | Задержка origin |
| `GET` | `/api/status/{code}` | Разрешённые тестовые статусы |
| `GET` | `/protected/admin` | Проверка path-rule |

## Настройки

| Переменная | По умолчанию | Описание |
|---|---:|---|
| `ADDR` | `:8080` | Адрес HTTP listener |
| `PORT` | — | Порт, если `ADDR` не задан |
| `APP_NAME` | `Yandex SWS Test Lab` | Название в UI |
| `MAX_BODY_BYTES` | `1048576` | Лимит тела, от 1 KiB до 10 MiB |
| `MAX_DELAY_MS` | `2000` | Верхняя граница `/api/slow`, до 10 s |
| `TRUST_PROXY_HEADERS` | `false` | Использовать `X-Forwarded-For` для effective IP |

Пример для закрытого backend за балансировщиком:

```bash
TRUST_PROXY_HEADERS=true ADDR=:8080 go run -buildvcs=false ./cmd/sws-lab
```

## Логи и приватность

Приложение пишет структурированные JSON-логи в stdout: request ID, метод, путь без query string, matched route, статус, размер ответа, длительность, effective client IP и User-Agent. Тела запросов, query values, Cookie и Authorization в лог не попадают. `/api/inspect` также возвращает только явный allowlist транспортных заголовков.

Счётчики находятся только в памяти и обнуляются при перезапуске. Сам `/api/stats` учитывается после формирования своего ответа, поэтому его текущий вызов виден только в следующем snapshot.

## Проверки проекта

```bash
make check
make test-race
```

В проекте нет сторонних Go-модулей.
