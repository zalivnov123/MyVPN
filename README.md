# MyVPN

Личный VPN: самодельный туннель на Go поверх SSH-транспорта.

```
[Windows ПК]                                  [VPS]
wintun-адаптер (10.8.0.2)                     TUN vpn0 (10.8.0.1)
      │                                             │
 vpn-client ── SSH (порт 442) ──> sshd ──> vpn-server (127.0.0.1:8443)
      │                                             │
 весь трафик ПК                          NAT → интернет
```

Транспорт — SSH, потому что DPI (ТСПУ) режет TLS-потоки к VPS-хостингам,
а SSH-трафик не трогает. Пакеты внутри канала: 2-байтовая длина + IP-пакет.

## Сборка

```bash
GOOS=linux   go build -o bin/vpn-server    ./cmd/server
GOOS=windows go build -o bin/vpn-client.exe ./cmd/client
```

Для клиента рядом с exe нужен `wintun.dll`
(из https://www.wintun.net/builds/wintun-0.14.1.zip, bin/amd64).

## Сервер (Ubuntu, systemd)

1. `cp bin/vpn-server /usr/local/bin/`, конфиг в `/etc/vpn/server.json`
   (шаблон — `configs/server.json.example`).
2. Пользователь для форвардинга:
   `useradd -m -s /usr/sbin/nologin vpn`, его `authorized_keys`:
   `no-pty,no-user-rc,no-agent-forwarding,no-X11-forwarding,permitopen="127.0.0.1:8443" <pubkey>`
3. sshd слушает порт 442 (у части провайдеров исходящий 22 закрыт).
4. ufw: `ufw default allow routed` (иначе forward-пакеты дропаются).
5. systemd unit: `ExecStart=/usr/local/bin/vpn-server -config /etc/vpn/server.json`,
   `Restart=always`. NAT и ip_forward поднимает сам сервер при старте.

## Клиент (Windows)

Запуск от администратора:

```
vpn-client.exe -config configs/client.json
```

Диагностика без туннеля (проверка транспорта): `vpn-client.exe -echo -config configs/client.json`

Клиент: поднимает wintun-адаптер, вешает на него IP и DNS, добавляет
маршрут /32 до сервера через физический шлюз и /1-маршруты через туннель.
При выходе (Ctrl+C) всё откатывает.

## Несколько устройств одновременно

Ключ и токен одни и те же на всех устройствах — просто скопируйте
`configs/client.json` и SSH-ключ. Сервер сам выдаёт каждому подключению
свой туннельный IP (10.8.0.2, 10.8.0.3, ...) и маршрутизирует ответы
нужному клиенту.
