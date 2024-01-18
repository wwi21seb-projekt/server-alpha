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