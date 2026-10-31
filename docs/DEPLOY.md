# Деплой control plane

Прод-приложение Dokploy `blockfield-control-plane` (`blockfield-control-plane-xwcxgx`,
private network only, без ingress) работает на digest-пине
`ghcr.io/blockfield/blockfield-control-plane@sha256:<digest>` (Docker provider:
только `dockerImage`, без registry credentials в полях приложения — авторизация идёт
через центральный GHCR registry). Канал `:latest` (его двигает `publish.yml` на каждый
merge в main) прод больше не отслеживает.

## Как деплоить

`Deploy control plane` (ручной dispatch, runner `blockfield-deploy` на homeserver):

1. `scripts/dokploy-pin.py deploy [sha256:<digest>]` — без аргумента пинит digest,
   который `:latest` отдаёт прямо сейчас (его только что собрал `publish.yml`).
2. Скрипт ставит `dockerImage` через Dokploy API (`application.saveDockerProvider`),
   перезапускает приложение (`application.redeploy`) и ждёт: все задачи служат
   digest, окно мониторинга swarm закрыто.
3. Проверка после деплоя: та же, что внутри скрипта, плюс `GET /v1/gate` из приватной
   сети отвечает со state, который был до деплоя (SQLite на volume `bf-control-state`
   пережил редеплой).

## Откат

Откат — повторный Deploy control plane с прежним digest (он же re-pin + redeploy;
скрипт при ошибке сам возвращает прежний работавший digest). Предыдущий digest виден
в логе прошлого run и в `application.one` (`dockerImage`). Publish отката не требует:
образ уже в registry. После отката проверить `/v1/openapi.json` из приватной сети.

## Одноразовая настройка (владелец)

Секреты репозитория (Settings → Secrets → Actions):

| Секрет              | Откуда взять                                   |
| ------------------- | ---------------------------------------------- |
| `DOKPLOY_API_URL`   | базовый URL дашборда Dokploy                   |
| `DOKPLOY_API_TOKEN` | Dokploy → настройки профиля → API/CLI          |

У Dokploy нет scoped-ролей: токен фактически административный, поэтому он живёт
только в секретах репозитория и используется только workflow деплоя. Токен никогда
не печатается в логи (только в заголовке `x-api-key`).
