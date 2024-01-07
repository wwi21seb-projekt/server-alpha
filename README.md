# Server-Alpha
Server Repository for the Alpha Group (1)

## Prerequisites

- [Docker](https://www.docker.com)
- [Docker Compose](https://docs.docker.com/compose/)

## Setup

1. Clone the repository.
2. Make sure Docker and Docker Compose are installed and running on your system.

This will start all the necessary containers for the service to run.

## Usage

### Start the Service

To start the service, navigate to the repository directory in your terminal and execute the following command:

```bash
./scripts/run.sh up
```

If you only want to start the database or the API, you can use the following commands:

```bash
./scripts/run.sh up db
```

```bash
./scripts/run.sh up app
```

### Clean up

To clean up the Docker volumes and containers, you can use the following command:

```bash
./scripts/run.sh clean
```

### Reset environment variables

If you want to reset the environment variables to their default values, you can use the following command:

```bash
./scripts/run.sh setup
```

### Stop the service

To stop the service, you can use the following command:

```bash
./scripts/run.sh down
```

or be more specific and only stop the database or the API:

```bash
./scripts/run.sh down db
```

```bash
./scripts/run.sh down app
```


## Configuration

The service can be configured via environment variables. The following variables are available:

| Variable          | Description                          | Default Value                                |
|-------------------|--------------------------------------|----------------------------------------------|
| `DB_HOST`         | The host of the database.            | `localhost`                                  |
| `DB_PORT`         | The port of the database.            | `5432`                                       |
| `DB_NAME`         | The name of the database.            | `server_alpha_db`                            |
| `DB_USER`         | The user of the database.            | `alpha`                                      |
| `DB_PASSWORD`     | The password of the database.        | `secret`                                     |
| `APP_PORT`        | The port of the API.                 | `8080`                                       |
| `ENVIRONMENT`     | The environment of the service.      | `development`                                |
| `JWT_PRIVATE_KEY` | The private key for JWT signing.     | `secret`                                     |
| `JWT_PUBLIC_KEY`  | The public key for JWT verification. | `secret`                                     |
| `MAILGUN_API_KEY` | The API key for Mailgun.             | `secret`                                     |
| `SERVER_IMAGE`    | The image of the server.             | `ghcr.io/wwi21seb-projekt/server-alpha:main` |


# Verbesserungsvorschläge/Änderungen

## 1 User

- [ ] **ALLE** API Ressourcen umbenennen (z.B. `users` -> `user`)

### Subscriptions
- [ ] `GET /users/:user/subscribers` -> Alle Subscriber, die dem User mit der ID `:user` folgen

- [ ] `GET /users/:user/subscriptions` -> Alle User, den der User mit der ID `:user` folgt
- [ ] `POST /users/:user/subscriptions` -> User mit der ID `:user` abonnieren
- [ ] `DELETE /users/:user/subscriptions` -> User mit der ID `:user` nicht mehr abonnieren

## 2 Posts
- [ ] `POST   /posts/` -> Post erstellen
- [ ] `GET    /posts/:postid` -> Post mit der ID `:postid`
- [ ] `PUT    /posts/:postid` -> Post mit der ID `:postid` aktualisieren
- [ ] `DELETE /posts/:postid` -> Post mit der ID `:postid` löschen

### 2.1 Feed
- [ ] `GET /feed/private` -> Privater Feed des Users
- [ ] `GET /feed/public` -> Öffentlicher Feed von allen Posts


### 2.2 Comments
- [ ] `GET /posts/:postid/comments` -> Alle Kommentare zu Post mit der ID `:postid`
- [ ] `POST /posts/:postid/comments` -> Kommentar zu Post mit der ID `:postid` hinzufügen
- [ ] `GET /posts/:postid/comments/:commentid` -> Kommentar mit der ID `:commentid` abrufen
- [ ] `PUT /posts/:postid/comments/:commentid` -> Kommentar mit der ID `:commentid` aktualisieren
- [ ] `DELETE /posts/:postid/comments/:commentid` -> Kommentar mit der ID `:commentid` löschen

### 2.3 Likes
- Posts
  - [ ] `GET /posts/:postid/likes` -> Alle Likes zu Post mit der ID `:postid` (Gibt eine Liste mit Usern zurück)
  - [ ] `POST /posts/:postid/likes` -> Like zu Post mit der ID `:postid` hinzufügen
  - [ ] `DELETE /posts/:postid/likes` -> Like zu Post mit der ID `:postid` entfernen
- Comments
  - [ ] `GET /posts/:postid/comments/:commentid/likes` -> Alle Likes zu Kommentar mit der ID `:commentid` (Gibt eine Liste mit Usern zurück)
  - [ ] `POST /posts/:postid/comments/:commentid/likes` -> Like zu Kommentar mit der ID `:commentid` hinzufügen
  - [ ] `DELETE /posts/:postid/comments/:commentid/likes` -> Like zu Kommentar mit der ID `:commentid` entfernen