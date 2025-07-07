# JWT Auth Service

Сервис аутентификации с поддержкой JWT (access) и refresh токенов, реализующий стандартные сценарии авторизации, обновления токенов, получения информации о пользователе и logout.

## Возможности
- Получение пары токенов (access + refresh) по GUID пользователя
- Обновление токенов по действующей паре
- Получение GUID текущего пользователя (защищённый эндпоинт)
- Деавторизация пользователя (logout)
- Swagger-документация с примерами ошибок и запросов

## Быстрый старт (Docker Compose)

```bash
git clone <repo-url>
cd jwt-auth
docker-compose up --build
```

- Сервис будет доступен на http://localhost:8082
- Swagger UI: http://localhost:8082/swagger/index.html
- Postgres поднимается автоматически

## Примеры запросов

### Получить токены
```bash
curl -X POST "http://localhost:8082/gettokens?guid=123e4567-e89b-12d3-a456-426614174000"
```

### Обновить токены
```bash
curl -X POST "http://localhost:8082/refresh" \
  -H "Content-Type: application/json" \
  -d '{"access_token": "<ACCESS>", "refresh_token": "<REFRESH>"}'
```

### Получить GUID текущего пользователя
```bash
curl -X GET "http://localhost:8082/user" \
  -H "Authorization: Bearer <ACCESS>"
```

### Logout
```bash
curl -X POST "http://localhost:8082/logout" \
  -H "Authorization: Bearer <ACCESS>"
```

## Swagger

Документация и примеры ошибок доступны по адресу:

- [http://localhost:8082/swagger/index.html](http://localhost:8082/swagger/index.html)

## Конфигурация

Используется файл `config/local.yaml`:

```yaml
token_ttl: "15m"
secret: "your_jwt_secret"
webhook_url: "http://example.com/webhook"
```

## Переменные окружения
- `CONFIG_PATH` — путь к YAML-конфигу (по умолчанию `/app/config/local.yaml`)
- `WEBHOOK_URL` — адрес для webhook при смене IP