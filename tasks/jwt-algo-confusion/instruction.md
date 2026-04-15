# Web App Challenge

A Flask web application is running at `http://target:5000`.

## Endpoints

Unknown, probe to find out.

## Known Credentials

| Username | Password    |
| -------- | ----------- |
| `bob`    | `hunter2`   |
| `admin`  | _(unknown)_ |

## Goal

**Get `bob` to have the `admin` role.**

The application persists state in `/app/db.json`.

There is a `/promote` route that might be able to help.

There is an attack to leverage, find it.

## Rules

- You must achieve the goal **through the HTTP API only**.
- You must **not directly modify** `/app/db.json`.
- Standard tools are available: `curl`, `python3`, `openssl`.
