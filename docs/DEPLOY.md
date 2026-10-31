# Деплой control plane

Прод-приложение Dokploy `blockfield-control-plane` (`blockfield-control-plane-xwcxgx`,
private network only, без ingress) работает с релизного канала
`ghcr.io/blockfield/blockfield-control-plane:prod` (Docker provider: только `dockerImage`,
без registry credentials в полях приложения — авторизация идёт через центральный GHCR
registry). Канал `:main` (его двигает `publish.yml` на каждый merge в main) прод не
отслеживает: только `Deploy control plane` двигает `:prod`, по digest.

## Как деплоить

`Deploy control plane` (ручной dispatch, runner `blockfield-deploy` на homeserver):

1. Digest из input workflow (или текущий `:main` — его только что собрал `publish.yml`).
2. `scripts/deploy-webhooks.py` переставляет `:prod` на этот digest
   (`docker buildx imagetools create`), дёргает webhook Dokploy и ждёт: лог деплоя
   показывает pull этого digest, все задачи служат его, окно мониторинга swarm закрыто.
   Несоответствие running digest релизному валит job.
3. Проверка после деплоя: та же, что внутри скрипта, плюс `GET /v1/gate` из приватной
   сети отвечает со state, который был до деплоя (SQLite на volume `bf-control-state`
   пережил редеплой).

## Откат

Откат — повторный Deploy control plane с прежним digest: скрипт двигает `:prod`
обратно и дёргает webhook (workflow делает это автоматически при ошибке деплоя).
Предыдущий digest виден в логе прошлого run. Publish отката не требует: образ уже
в registry. После отката проверить `/v1/openapi.json` из приватной сети.

## Одноразовая настройка (владелец)

Секрет репозитория (Settings → Secrets → Actions):

| Секрет               | Откуда взять                 |
| -------------------- | ---------------------------- |
| `DOKPLOY_CP_WEBHOOK` | Dokploy → приложение → Webhook |

API-ключа Dokploy в Actions нет: деплой идёт через webhook приложения, как у proxy
и сервера. Переключение приложения `blockfield-control-plane-xwcxgx` с `:latest`
на `:prod` делает координатор через Dokploy (порядок: сначала запушить `:prod`,
потом переключить `dockerImage`).
