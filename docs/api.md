# PrivacyGuard AI API

Base URL: `/api`

## Public

- `GET /health`
- `POST /auth/register`
- `POST /auth/login`

## JWT protected

- `GET /auth/me`
- `POST /analyze` — JSON `{text,title}` or multipart `file`
- `POST /scans/<id>/sanitize` — JSON `{mode}`
- `GET /scans`
- `GET /scans/<id>`
- `GET /scans/<id>/report`
- `GET /dashboard`
- `GET /audit`
