| Ticket                                   | METHODE                                 | Endpunkt                             | Beschreibung               | Implementiert |
|------------------------------------------|-----------------------------------------|--------------------------------------|----------------------------|---------------|
| [Trello Ticket 1]                        | <span style="color:yellow">POST</span>  | `/users`                             | Create User                | ✅             |
| [Trello Ticket 1]                        | <span style="color:yellow">POST</span>  | `/users/:username/activate`          | Activate User              | ✅             |
| [Trello Ticket 1]                        | <span style="color:red">DELETE</span>   | `/users/:username/activate`          | Resend token               | ✅             |
| [Trello Ticket 1]                        | <span style="color:yellow">POST</span>  | `/users/login`                       | Login                      | ✅             |
| [Trello Ticket 2]                        | <span style="color:green">GET</span>    | `/imprint`                           | Impressum                  | ✅             |
| [Trello Ticket 3.1], [Trello Ticket 3.2] | <span style="color:yellow">POST</span>  | `/posts`                             | Create Posts               | ✅             |
| [Trello Ticket 5]                        | <span style="color:green">GET</span>    | `/users/:username`                   | Visit User Profile         | ✅             |
| [Trello Ticket 4]                        | <span style="color:green">GET</span>    | `/users?username&offset&limit`       | Search User                | ✅             |
| [Trello Ticket 4]                        | <span style="color:green">GET</span>    | `/users/:username/feed?offset&limit` | User Feed                  | ❌             |
| [Trello Ticket 4]                        | <span style="color:yellow">POST</span>  | `/subscriptions`                     | Subscribe User             | ✅             |
| [Trello Ticket 4]                        | <span style="color:red">DELETE</span>   | `/subscriptions/:subscriptionId`     | Unsubscribe User           | ✅             |
| [Trello Ticket 6.1]                      | <span style="color:green">GET</span>    | `/feed?postId&limit&feedType`        | Get own or global feed     | ✅             |
| [Trello Ticket 6.2]                      | <span style="color:green">GET</span>    | `/feed?postId&limit`                 | Get global feed (no auth)  | ✅             |
| [Trello Ticket 7]                        | <span style="color:blue">PUT</span>     | `/users`                             | Change trivial information | ✅             |
| [Trello Ticket 7]                        | <span style="color:purple">PATCH</span> | `/users`                             | Change password            | ✅             |

[Trello Ticket 1]: https://trello.com/c/1w0QP6u5/209-id-0-als-nutzer-möchte-ich-mich-mit-email-und-passwort-registrieren-können-um-einen-gesicherten-zugang-zu-meinem-account-zu-habe

[Trello Ticket 2]: https://trello.com/c/iYqk0soU/65-id-1-als-nutzender-möchte-ich-wissen-wer-diese-webseite-betreibt-impressum-um-den-inhaber-erreichen-zu-können

[Trello Ticket 3.1]: https://trello.com/c/4EFATTw5/16-id-3-als-nutzer-möchte-ich-texte-posten-können-um-meine-gedanken-zu-teilen

[Trello Ticket 3.2]: https://trello.com/c/TFa4slAY/44-id-1-als-nutzer-möchte-ich-die-möglichkeit-haben-hashtags-zu-verwenden-um-meine-beiträge-zu-kategorisieren-und-leichter-auffindb

[Trello Ticket 4]: https://trello.com/c/pMKGBdKc/34-id-8-als-nutzer-möchte-ich-die-möglichkeit-haben-andere-nutzer-zu-suchen-und-ihre-persönlichen-nachrichten-feeds-anzeigen-zu-kön

[Trello Ticket 5]: https://trello.com/c/7n9UqgFT/35-id-6-als-nutzer-möchte-ich-die-option-haben-nutzerprofile-einzusehen-und-grundlegende-informationen-über-sie-zu-erhalten

[Trello Ticket 6.1]: https://trello.com/c/5DqWr7nd/60-id-5-als-nutzer-möchte-ich-einen-feed-haben-um-neue-beiträge-meiner-freunde-sehen-zu-können

[Trello Ticket 6.2]: https://trello.com/c/bNi7BJlb/210-id-7-als-nutzer-möchtet-ich-auch-unangemeldet-einen-feed-haben-der-letzten-beiträge

[Trello Ticket 7]: https://trello.com/c/zik6TGN5/30-id-2-als-nutzer-möchte-ich-meinem-account-konfigurieren-können-passwort-ändern-nickname-ändern
