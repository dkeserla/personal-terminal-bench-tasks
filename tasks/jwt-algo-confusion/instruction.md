# JWT Privilege Escalation

A Flask web application is running at `http://localhost:5000`.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/login?username=<u>&password=<p>` | Authenticate and receive a JWT |
| `GET` | `/users` | List all users and their current roles (public) |
| `GET` | `/public-key` | Return the server's RSA public key in PEM format |
| `POST` | `/promote` | Promote a user to admin (requires admin JWT) |

The `/promote` endpoint expects:
- Header: `Authorization: Bearer <token>`
- Body: `{"username": "<target_username>"}`

## Known Credentials

| Username | Password |
|----------|----------|
| `bob` | `hunter2` |
| `admin` | *(unknown)* |

## Goal

**Promote the user `bob` to the `admin` role.**

After you are done, the application state must reflect that `bob` has `role: "admin"`. The application persists state in `/app/db.json`.

## Rules

- You must achieve the goal **through the HTTP API only**.
- You must **not directly modify** `/app/db.json`.
- Standard tools are available: `curl`, `python3`, `openssl`.
