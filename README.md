# QUIC Relay

## Protocol

Client->Server
    GET /rooms\r\n
    X-MY-ROOM-ID: <room_id>\r\n
    \r\n
Client<-Server HTTP
    HTTP/1.1 200 OK\r\n
    \r\n

サーバーは、同じ <room_id> と同じリクエストを送ってきたクライアントを紐付ける。
紐付けられたクライアントがサーバーに送ったデータは、サーバーによって、他のクライアントへデータが送られる。

```
git submodule update --init --recursive

```