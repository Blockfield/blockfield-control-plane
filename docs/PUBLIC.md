# Публичная точка входа control plane

CP работает дважды из одного образа:

- внутренний экземпляр (по умолчанию): полный API, заголовок `X-CP-Public`
  игнорируется полностью — перевести его в публичный режим запросом нельзя;
- публичный экземпляр (`CP_PUBLIC_ONLY=1`): только точный allowlist ниже,
  со своими лимитами соединений, пулом БД и бюджетами.

Публичный домен ведёт только на публичный экземпляр (маршрут Traefik, см.
настройку ниже). Внутренний экземпляр остаётся private network only, без
домена и без опубликованного порта.

## Что разрешено снаружи

Точный список, ничего сверх (хит-рег и диагностика — только для персонала,
никогда не публичны):

- `GET`/`HEAD /health`
- `GET`/`HEAD /v2/stats/seasons`, `/v2/stats/leaderboard`, `/v2/stats/players/{uuid}`
  — анонимно, без токена (решение владельца «Без токена»); токен бота со
  скопом `stats.read` тоже работает;
- `POST /v2/actions/console.run` — только аутентифицированно; скоп решает:
  `console.read` выполняет лишь read-only allowlist, остальное — `403`
  (исполнение не-read-only строк идёт через approval-relay, см. ниже);
- `GET /v2/operations/{id}` — только аутентифицированно, только своя операция
  (читает выпустивший креденшел; чужое — `403`/`404`).

Всё остальное на публичном экземпляре отвечает `404`, даже с валидным
токеном. Тот же запрос внутри приватной сети работает как обычно — решает
аутентификация. Продление креденшела (`/v2/credentials/renew`) снаружи
недоступно.

## Лимиты публичного экземпляра

Независимо от внутреннего бюджета (1000/мин на аутентифицированные запросы):

- pre-auth бюджет до любых проверок и обращений к БД: per-IP 120/мин плюс
  общий публичный 2000/мин (тот же счётчик);
- per-ключ: 120/мин; per-token: 60/мин;
- неверная аутентификация списывается с отдельного малого бюджета (100/мин):
  внутренний вызов с неверным bearer получает `401` от внутреннего бюджета,
  флуд снаружи на это не влияет;
- пул БД публичного экземпляра — свой (`CP_DB_POOL_MAX`, по умолчанию 4
  против 8 у внутреннего), соединения/лимиты — свои
  (`CP_LIMIT_CONCURRENCY`, по умолчанию 32 против 96);
- анонимные чтения статистики кешируются на 20 с.

## Переменные окружения

| Переменная                  | Внутренний | Публичный            |
| --------------------------- | ---------- | -------------------- |
| `CP_PUBLIC_ONLY`            | unset      | `1`                  |
| `CP_LIMIT_CONCURRENCY`      | `96`       | `32`                 |
| `CP_DB_POOL_MAX`            | `8`        | `4`                  |
| `CP_PUBLIC_TRUSTED_PROXIES` | —          | список прокси (ниже) |

`CP_PUBLIC_TRUSTED_PROXIES` — адреса/CIDR прокси перед CP через запятую
(обычно адрес Traefik в docker-сети). Пусто по умолчанию: все запросы
кладутся на адрес соединения. IPv6 ключируется по /64 (один /64 — один
бакет), `::ffff:1.2.3.4` — как IPv4, записи с портом разбираются, мусор в
цепочке — откат на адрес соединения.

## Настройка Traefik/Dokploy (делает владелец, в этом PR не применено)

1. Второй Dokploy-сервис из того же образа с `CP_PUBLIC_ONLY=1` и своим
   `CP_PORT`; внутренний сервис остаётся без домена.
2. Один роутер: точное `Host`-правило публичного домена на HTTPS entrypoint,
   сервис — только публичный экземпляр. Никакого Dokploy-домена на CP,
   никакого catch-all/path-only роутера, никакого опубликованного порта
   контейнера.
3. Клиентское значение `X-CP-Public` снимать (на всякий случай: CP его
   игнорирует, но пусть не путешествует дальше).
4. Фильтр метода и пути на краю, чтобы ошибка роутинга ничего не открыла:
   `Method(GET,HEAD)` + точные пути, отдельным правилом — `Method(POST)` +
   `Path(/v2/actions/console.run)` и `Method(GET)` + `PathPrefix(/v2/operations/)`.
5. Доверенные адреса: на публичном entrypoint в `forwardedHeaders.trustedIPs`
   указать реальные апстрим-прокси, и те же адреса — в
   `CP_PUBLIC_TRUSTED_PROXIES` публичного экземпляра.
6. Лимиты раньше CP: `inFlightReq` (существенно ниже 32, по хосту) плюс
   `rateLimit` по адресу клиента.
7. Таймауты read/write/idle на entrypoint — явно (у uvicorn нет таймаута
   заголовка). Только HTTPS (редирект/отказ plain HTTP). Access log без
   заголовков; без retry и CORS middlewares на этом роутере. Заголовки
   безопасности ставит сам CP; 503 Traefik/uvicorn их не несут — при желании
   продублировать `headers` middleware на роутере.

```yaml
http:
  routers:
    cp-public-get:
      rule: "Host(`<public-domain>`) && (Method(`GET`) || Method(`HEAD`)) && (Path(`/health`) || Path(`/v2/stats/seasons`) || Path(`/v2/stats/leaderboard`) || PathPrefix(`/v2/stats/players/`) || PathPrefix(`/v2/operations/`))"
      entryPoints: [websecure]
      service: <cp-public-service>
      middlewares: [cp-public-strip, cp-public-inflight, cp-public-rate]
    cp-public-console-run:
      rule: "Host(`<public-domain>`) && Method(`POST`) && Path(`/v2/actions/console.run`)"
      entryPoints: [websecure]
      service: <cp-public-service>
      middlewares: [cp-public-strip, cp-public-inflight, cp-public-rate]
  middlewares:
    cp-public-strip:
      headers:
        customRequestHeaders:
          X-CP-Public: ""
    cp-public-inflight:
      inFlightReq:
        amount: 16
        sourceCriterion:
          requestHost: true
    cp-public-rate:
      rateLimit:
        average: 4
        burst: 20
```

8. Health check Dokploy остаётся внутренним `GET /health` (см. [DEPLOY](DEPLOY.md));
   на публичном экземпляре `/health` отдаёт только `{"status":"ok"}` без версии схемы.
