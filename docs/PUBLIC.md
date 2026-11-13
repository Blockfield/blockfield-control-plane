# Публичная точка входа control plane

CP держит доступ из интернета на отдельной публичной точке входа, а не на
приватном приложении. Приложение Dokploy `blockfield-control-plane` остаётся
private network only, без ingress: публичный домен ведёт на CP только через
маршрут Traefik, который ставит заголовок `X-CP-Public: 1` (код:
[`app.py`](../cpv2/app.py) `PUBLIC_ENTRYPOINT_HEADER`, `public_allowed`).

## Что разрешено снаружи

Allowlist публичного маршрута — только пробы и чтения статистики:

- `GET /health`
- `GET /v2/stats/*`

Всё остальное (actions, acks, operations, settings, console, agents, audit,
openapi) на публичном маршруте отвечает `404`, даже с валидным токеном.
Тот же запрос внутри приватной сети работает как обычно — решает аутентификация.

## Лимиты публичного маршрута

Независимо от общего бюджета (1000/мин на аутентифицированные запросы):

- per-IP: 120/мин;
- per-token: 60/мин (одного токена лаунчера/бота хватает с запасом: опрос статистики идёт раз в десятки секунд).

Флуд снаружи не сжигает бюджет внутренних агентов: бюджеты не пересекаются.

## Заголовки и лимиты тела

Каждый ответ несёт:

- `Strict-Transport-Security: max-age=3153600; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
- `Cache-Control: no-store`

Лимиты тела запроса (413 сверх лимита):

| Путь                    | Лимит |
| ----------------------- | ----- |
| `/v2/stats/results`     | 1 МБ  |
| `/v2/stats/diagnostics` | 1 МБ  |
| `/v2/console/logs`      | 64 КБ |
| `/v2/console/suggest`   | 4 КБ  |
| остальные мутации       | 32 КБ |

## Настройка Traefik/Dokploy (делает владелец, в этом PR не применено)

1. Публичный домен ведёт на CP отдельным маршрутом Traefik (не ingress
   приватного приложения, оно остаётся без домена).
2. Маршрут снимает клиентское значение `X-CP-Public`, если оно пришло
   снаружи, и ставит `X-CP-Public: 1` — только этот маршрут вправе его ставить.
   Заголовку можно доверять: прямой доступ в контейнер требует root homeserver.
3. Пример фрагмента file provider (имена — под стенд владельца):

   ```yaml
   http:
     routers:
       cp-public:
         rule: "Host(`cp.example.com`)"
         service: blockfield-control-plane
         middlewares: [cp-public-headers]
     middlewares:
       cp-public-headers:
         headers:
           customRequestHeaders:
             X-CP-Public: "1"
   ```

   Если между клиентом и Traefik есть ещё прокси, он тоже должен снимать
   входящий `X-CP-Public` до Traefik.

4. Лимит per-IP считает адрес клиента из `X-Forwarded-For`: берётся запись,
   которую дописал доверенный прокси, записи левее игнорируются. Число
   доверенных прокси перед CP задаёт `CP_PUBLIC_TRUSTED_HOPS` (по умолчанию 1 —
   только Traefik). Если перед Traefik стоит ещё один прокси, поставьте 2,
   иначе все клиенты за ним разделят один лимит.

5. Health check Dokploy остаётся внутренним `GET /health` (см. [DEPLOY](DEPLOY.md));
   публичный маршрут его не заменяет.
