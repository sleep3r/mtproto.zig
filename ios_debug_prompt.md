# Контекст
Я пишу MTProto прокси для Telegram на **Zig 0.15**. Прокси маскирует трафик под обычный TLS 1.3 (FakeTLS). 
Сервер использует классическую блокирующую архитектуру "один поток на соединение" (`std.Thread.spawn`).

# Проблема
Прокси отлично работает на десктопных клиентах (macOS/Windows Telegram). Однако на **мобильном клиенте iOS** он не подключается: висит «Соединение...» или показывает, что прокси недоступен.
При этом в серверных логах в этот момент массово сыпятся ошибки тайм-аута при чтении сокета:
```text
error(proxy): [451] Connection error: error.WouldBlock
error(proxy): [448] Connection error: error.WouldBlock
error(proxy): [452] Connection error: error.WouldBlock
```

# Детали реализации и гипотеза

1. При подключении клиента мы спавним новый поток и вызываем `handleConnection`.
2. Чтобы защититься от Slowloris во время TLS хендшейка, мы выставляем на сокет `SO_RCVTIMEO` на 30 секунд.
3. Прокси пытается прочитать 5 байт заголовка TLS `ClientHello` через `readExact`.
4. Клиент Telegram на iOS открывает TCP-соединение, но ничего не отправляет. Через 30 секунд `stream.read` отваливается по тайм-ауту с `EAGAIN` (`error.WouldBlock`).
5. Мы ловим эту ошибку, логируем ее и закрываем сокет.

**Гипотеза:** Клиент Telegram на iOS использует **пул соединений (connection pooling)** для экономии заряда батареи: он превентивно открывает пачку фоновых TCP-подключений и держит их открытыми (idle), не отправляя первый пакет сразу. Наш прокси убивает эти idle-трэды через 30 секунд, из-за чего iOS считает, что прокси нестабильный или не работает, и рвет сессию.

# Код `src/proxy/proxy.zig`

Вот проблемные участки кода:

```zig
const std = @import("std");
const net = std.net;
const posix = std.posix;

// 1. Тайм-аут ожидания первого пакета
const handshake_timeout_sec = 30;

fn setRecvTimeout(fd: posix.fd_t, timeout_sec: u32) void {
    const tv = posix.timeval{ .sec = @intCast(timeout_sec), .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch return;
}

// 2. Чтение данных
fn readExact(stream: net.Stream, buf: []u8) !usize {
    var total: usize = 0;
    while (total < buf.len) {
        const nr = stream.read(buf[total..]) catch |err| {
            if (total > 0) return total;
            return err; // <-- Возвращает error.WouldBlock после истечения 30 секунд
        };
        if (nr == 0) return total;
        total += nr;
    }
    return total;
}

// 3. Обработчик соединения
fn handleConnectionInner(
    state: *ProxyState,
    client_stream: net.Stream,
    conn_id: u64,
) !void {
    // Выставляем SO_RCVTIMEO на сокет
    setRecvTimeout(client_stream.handle, handshake_timeout_sec);

    var tls_header: [5]u8 = undefined;
    
    // Блокируется тут: iOS ничего не прислала, падаем с error.WouldBlock
    if (try readExact(client_stream, &tls_header) < 5) return;
    
    if (tls_header[0] != constants.tls_record_application) return;
    // ... (дальнейшая логика FakeTLS хендшейка)
}

// 4. Обертка потока, которая логирует ошибку
fn handleConnection(
    state: *ProxyState,
    client_stream: net.Stream,
    peer_addr: net.Address,
    conn_id: u64,
) void {
    defer client_stream.close();

    handleConnectionInner(state, client_stream, conn_id) catch |err| {
        // Мы видим спам именно отсюда
        log.err("[{d}] Connection error: {any}", .{ conn_id, err });
    };
}
```

# Вопросы

1. Права ли гипотеза `connection pooling` в iOS Telegram-клиенте, и почему десктопные клиенты ведут себя иначе? 
2. Как элегантно исправить это в архитектуре "thread-per-connection" на Zig без перехода на `epoll/kqueue`?
   (Например: убрать `SO_RCVTIMEO` и сделать poll() на первый байт с длинным тайм-аутом, или просто молча глушить `error.WouldBlock`?)
3. Если мы оставим `std.Thread.spawn` и увеличим timeout для idle соединений до 5-10 минут, не убьет ли это RAM / лимит потоков ОС при наплыве подключений от iOS (сколько соединений в пуле генерирует iOS)?
