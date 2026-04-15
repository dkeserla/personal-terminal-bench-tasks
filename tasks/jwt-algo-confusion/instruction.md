# Web App Challenge

A Flask web application is running at `http://localhost:5000`.

## Endpoints

| Method | Path                               |
| ------ | ---------------------------------- |
| `GET`  | `/login?username=<u>&password=<p>` |
| `GET`  | `/users`                           |
| `GET`  | `/public-key`                      |
| `POST` | `/forgot-password`                 |
| `POST` | `/reset-password`                  |
| `POST` | `/promote`                         |

## Known Credentials

| Username | Password    |
| -------- | ----------- |
| `bob`    | `hunter2`   |
| `admin`  | _(unknown)_ |

## Starting Point

Bob's JWT (valid for 1 hour after login):

```
BOB_TOKEN=$(curl -s 'http://localhost:5000/login?username=bob&password=hunter2' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

## Goal

**Get `bob` to have the `admin` role.**

The application persists state in `/app/db.json`.

There is a `/promote` route that might be able to help.

## Rules

- You must achieve the goal **through the HTTP API only**.
- You must **not directly modify** `/app/db.json`.
- Standard tools are available: `curl`, `python3`, `openssl`.
