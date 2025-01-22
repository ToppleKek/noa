/**
    Noa HTTP 1.1/WebSocket 13 server.

    Author: Braeden Hong
    Date:   2024/10/29 to 2024/11/03
*/

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>
#include <math.h>

#include "noa.h"

#define NOA_SHA1_IMPLEMENTATION
#include "thirdparty/sha1.h"

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t   i8;
typedef int16_t  i16;
typedef int32_t  i32;
typedef int64_t  i64;

typedef float    f32;
typedef double   f64;

typedef intptr_t  iptr;
typedef uintptr_t uptr;
typedef i64       isize;
typedef size_t    usize;

#define null  NULL
#define false 0
#define true  1

#define ARRAY_LEN(ARR)           (sizeof(ARR) / sizeof(ARR[0]))
#define SET_FLAG(FLAGS, FLAG)    (FLAGS |= FLAG)
#define CLEAR_FLAG(FLAGS, FLAG)  (FLAGS &= ~FLAG)
#define FLAG_IS_SET(FLAGS, FLAG) (FLAGS & FLAG)
#define KILOBYTES(N)             (N * 1024)
#define MEGABYTES(N)             (N * KILOBYTES(1024))
#define NOA_INFO(fmt, ...)       printf("(info) %s:%d: " fmt "\n", __FILE__, __LINE__ __VA_OPT__(, ) __VA_ARGS__)
#define NOA_ERROR(fmt, ...)      printf("(error) %s:%d: " fmt "\n", __FILE__, __LINE__ __VA_OPT__(, ) __VA_ARGS__)

#if defined(_WIN32)
#pragma comment(lib, "Ws2_32")
#define alloca _alloca
#define SOCKET_FMT "%llu"

typedef struct pollfd PlatformPollfd;

typedef struct {
    PlatformSocket fd;
    struct pollfd pfd;
} Listener;

static PlatformPollfd platform_create_pollfd(PlatformSocket socket) {
    return (PlatformPollfd) {
        socket,
        POLLRDNORM,
        0,
    };
}

static inline void platform_invalidate_pollfd(PlatformPollfd *pfd) {
    pfd->fd = PLATFORM_INVALID_SOCKET;
}

static Listener platform_init_listener(const char *address, u16 port) {
    Listener listener;
    WSADATA wsa;
    assert(WSAStartup(MAKEWORD(2,2), &wsa) == 0);

    listener.fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family  = AF_INET;
    server_addr.sin_port    = htons(port);
    InetPton(AF_INET, address, &server_addr.sin_addr.S_un.S_addr);

    assert(bind(listener.fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != SOCKET_ERROR);
    assert(listen(listener.fd, 10) != SOCKET_ERROR);

    // Set non-blocking IO mode so we can poll for new connections
    u32 imode = 1;
    ioctlsocket(listener.fd, FIONBIO, &imode);

    listener.pfd = (struct pollfd) {
        listener.fd,
        POLLRDNORM,
        0,
    };

    return listener;
}

static i32 platform_poll_listener(Listener *listener, i32 timeout) {
    i32 result = WSAPoll(&listener->pfd, 1, timeout);
    if (result == SOCKET_ERROR) {
        NOA_ERROR("(poll) socket error: %d", WSAGetLastError());
        return PLATFORM_SOCKET_ERROR;
    }

    return result;
}

static u32 platform_found_connections(Listener *listener) {
    return platform_poll_listener(listener, 1) > 0 && listener->pfd.revents & POLLRDNORM;
}

static u32 platform_accept(Listener *listener) {
    return accept(listener->fd, null, null);
}

static i32 platform_socket_has_data(PlatformSocket socket, u32 timeout) {
    struct pollfd poll_listen_fd = {
        socket,
        POLLRDNORM,
        0,
    };

    return WSAPoll(&poll_listen_fd, 1, timeout) > 0 && poll_listen_fd.revents & POLLRDNORM;
}

static inline i32 platform_socket_pfd_has_data(PlatformPollfd pfd) {
    return pfd.revents & POLLRDNORM;
}

static i32 platform_poll(PlatformPollfd *pfd, u32 count, u32 timeout) {
    return WSAPoll(pfd, count, timeout);
}

static i32 platform_recv(PlatformSocket socket, u8 *buffer, usize buffer_size, u32 timeout) {
    if (platform_socket_has_data(socket, timeout))
        return recv(socket, (char *) buffer, buffer_size, 0);

    return PLATFORM_RECV_ERROR;
}


static i32 platform_send(PlatformSocket socket, u8 *buffer, usize size) {
    return send(socket, (char *) buffer, size, 0);
}

static void platform_close(PlatformSocket socket) {
    closesocket(socket);
}
#elif defined(unix)
#define SOCKET_FMT "%d"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <unistd.h>
#include <alloca.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>

typedef struct pollfd PlatformPollfd;

typedef struct {
    PlatformSocket fd;
    struct pollfd pfd;
} Listener;

static inline PlatformPollfd platform_create_pollfd(PlatformSocket socket) {
    return (PlatformPollfd) {
        socket,
        POLLRDNORM,
        0,
    };
}

static inline void platform_invalidate_pollfd(PlatformPollfd *pfd) {
    pfd->fd = PLATFORM_INVALID_SOCKET;
}

static Listener platform_init_listener(const char *address, u16 port) {
    signal(SIGPIPE, SIG_IGN);
    Listener listener;

    listener.fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    i32 b = 1;
    setsockopt(listener.fd, SOL_SOCKET, SO_REUSEADDR, &b, sizeof(i32));

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family  = AF_INET;
    server_addr.sin_port    = htons(port);
    inet_pton(AF_INET, address, &server_addr.sin_addr);

    // assert(bind(listener.fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != PLATFORM_SOCKET_ERROR);
    if (bind(listener.fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == PLATFORM_SOCKET_ERROR) {
        NOA_ERROR("bind failed: %d", errno);
        exit(1);
    }

    if (listen(listener.fd, 10) == PLATFORM_SOCKET_ERROR) {
        NOA_ERROR("listen failed: %d", errno);
        exit(1);
    }

    // Set non-blocking IO mode so we can poll for new connections
    u32 imode = 1;
    ioctl(listener.fd, FIONBIO, &imode);

    listener.pfd = (struct pollfd) {
        listener.fd,
        POLLRDNORM,
        0,
    };

    return listener;
}

static i32 platform_poll_listener(Listener *listener, i32 timeout) {
    i32 result = poll(&listener->pfd, 1, timeout);
    if (result == PLATFORM_SOCKET_ERROR) {
        NOA_ERROR("(poll) socket error: %d", errno);
        return PLATFORM_SOCKET_ERROR;
    }

    return result;
}

static u32 platform_found_connections(Listener *listener) {
    return platform_poll_listener(listener, 0) > 0 && listener->pfd.revents & POLLRDNORM;
}

static u32 platform_accept(Listener *listener) {
    return accept(listener->fd, null, null);
}

static i32 platform_socket_has_data(PlatformSocket socket, u32 timeout) {
    struct pollfd poll_listen_fd = {
        socket,
        POLLRDNORM,
        0,
    };

    return poll(&poll_listen_fd, 1, timeout) > 0 && poll_listen_fd.revents & POLLRDNORM;
}

static inline i32 platform_socket_pfd_has_data(PlatformPollfd pfd) {
    return pfd.revents & POLLRDNORM;
}

static i32 platform_poll(PlatformPollfd *pfd, u32 count, u32 timeout) {
    return poll(pfd, count, timeout);
}

static i32 platform_recv(PlatformSocket socket, u8 *buffer, usize buffer_size, u32 timeout) {
    if (platform_socket_has_data(socket, timeout))
        return recv(socket, (char *) buffer, buffer_size, 0);

    return PLATFORM_RECV_ERROR;
}

static i32 platform_send(PlatformSocket socket, u8 *buffer, usize size) {
    return send(socket, (char *) buffer, size, 0);
}

static void platform_close(PlatformSocket socket) {
    close(socket);
}
#else
#error Unsupported platform
#endif

typedef struct {
    usize capacity;
    usize size;
    char *data;
} StringBuffer;

StringBuffer noa_sb_create(usize initial_capacity) {
    StringBuffer sb;
    sb.capacity = initial_capacity;
    sb.size     = 0;
    sb.data     = malloc(initial_capacity);
    return sb;
}

static void noa_sb_maybe_resize(StringBuffer *sb, usize new_bytes) {
    usize capacity_needed = sb->size + new_bytes;
    if (capacity_needed > sb->capacity) {
        usize new_capacity = sb->capacity * 2 + capacity_needed;
        sb->data           = realloc(sb->data, new_capacity);
        sb->capacity       = new_capacity;
    }
}

static usize noa_sb_append_bytes(StringBuffer *sb, const char *bytes, usize len) {
    noa_sb_maybe_resize(sb, len);

    memcpy(&sb->data[sb->size], bytes, len);
    sb->size += len;

    return len;
}

static usize noa_sb_append_byte(StringBuffer *sb, const char c) {
    noa_sb_maybe_resize(sb, 1);
    sb->data[sb->size++] = c;
    return 1;
}

static inline usize noa_sb_append_cstr(StringBuffer *sb, const char *str) {
    return noa_sb_append_bytes(sb, str, strlen(str));
}

static usize noa_sb_append_u32(StringBuffer *sb, u32 n) {
    if (n == 0) {
        noa_sb_append_byte(sb, '0');
        return 1;
    }

    u32 digits = log10(n) + 1;
    noa_sb_maybe_resize(sb, digits);

    char *buf = alloca(digits);

    for (u32 i = 0; n > 0; n /= 10, ++i)
        buf[i] = (n % 10) + '0';

    for (i32 i = digits - 1; i >= 0; --i)
        sb->data[sb->size++] = buf[i];

    return digits;
}

static inline void noa_sb_reset(StringBuffer *sb) {
    sb->size = 0;
}

static void noa_sb_delete(StringBuffer *sb) {
    free(sb->data);
    memset(sb, 0, sizeof(StringBuffer));
}

static i32 str_equal_case_insensitive(const char *lhs, const char *rhs) {
    for (;; ++lhs, ++rhs) {
        if (*lhs == '\0' || *rhs == '\0')
            return *lhs == '\0' && *rhs == '\0';

        if (tolower(*lhs) != tolower(*rhs))
            return false;
    }

    return true;
}

static const char base64_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static StringBuffer noa_base64_encode(u8 *str, usize len) {
    StringBuffer ret = noa_sb_create(512);
    for (usize i = 0; i < len; i += 3) {
        u8 b[4];
        b[0] = base64_alphabet[str[i] >> 2];

        if (i + 1 >= len) {
            b[1] = base64_alphabet[(str[i] & 0b11) << 4];
            b[2] = '=';
            b[3] = '=';
        } else if (i + 2 >= len) {
            b[1] = base64_alphabet[((str[i] & 0b11) << 4) | (str[i + 1] >> 4)];
            b[2] = base64_alphabet[(str[i + 1] & 0b1111) << 2];
            b[3] = '=';
        } else {
            b[1] = base64_alphabet[((str[i] & 0b11) << 4) | (str[i + 1] >> 4)];
            b[2] = base64_alphabet[((str[i + 1] & 0b1111) << 2) | (str[i + 2] >> 6)];
            b[3] = base64_alphabet[str[i + 2] & 0b111111];
        }

        noa_sb_append_bytes(&ret, (char *) b, 4);
    }

    return ret;
}

// Push buffer arena allocator
typedef struct {
    u64 pointer;
    u64 capacity;
    u8 *data;
} Arena;

#define PUSH_STRUCT(ARENA, S) push_struct(&ARENA, &S, sizeof(S))
#define PUSH_ARRAY(ARENA, TYPE, COUNT) (TYPE *) push_array(&ARENA, sizeof(TYPE), COUNT)
#define BEGIN_LIST(ARENA, TYPE) (TYPE *) (&ARENA.data[ARENA.pointer])
#define BEGIN_TEMP_MEMORY(ARENA) (ARENA.pointer)
#define END_TEMP_MEMORY(ARENA, POINTER) (ARENA.pointer = POINTER)
#define RESET_ARENA(ARENA) ARENA.pointer = 0
static void *push_struct(Arena *arena, void *s, u64 len) {
    if (arena->pointer + len > arena->capacity) {
        assert(false && "Out of memory");
        return null;
    }

    void *ret = &arena->data[arena->pointer];
    memcpy(ret, s, len);
    arena->pointer += len;
    return ret;
}

static void *push_array(Arena *arena, usize size, usize count) {
    usize len = size * count;

    if (arena->pointer + len > arena->capacity) {
        assert(false && "Out of memory");
        return null;
    }

    void *ret = &arena->data[arena->pointer];
    arena->pointer += len;
    return ret;
}

static char recv_buffer[MEGABYTES(16)];
static u8 mem[MEGABYTES(64)];
static Arena arena = {0, sizeof(mem), mem};

static usize next_non_whitespace_index(char *buf, usize buf_size, usize i) {
    for (; i < buf_size && isspace(buf[i]); ++i);
    return i;
}

// https://www.rfc-editor.org/rfc/rfc9110.html#name-collected-abnf
// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
static inline i32 is_tchar(char c) {
    return (
        isalpha(c) ||
        isdigit(c) ||
        c == '!'   ||
        c == '#'   ||
        c == '$'   ||
        c == '%'   ||
        c == '&'   ||
        c == '\''  ||
        c == '*'   ||
        c == '+'   ||
        c == '-'   ||
        c == '.'   ||
        c == '^'   ||
        c == '_'   ||
        c == '`'   ||
        c == '|'   ||
        c == '~'
   );
}

#define NOA_MAX_FIELDS 32

static NoaRequest parse_http_request(char *buf, usize buf_size) {
    // Parse control data
    NoaRequest request = {0};
    char *method       = alloca(16);

    u32 i = 0;
    for (; i < 15 && i < buf_size && !isspace(buf[i]); ++i) {
        method[i] = buf[i];
    }

    method[i] = 0;
    if      (strcmp(method, "GET")     == 0) request.method = NOA_METHOD_GET;
    else if (strcmp(method, "HEAD")    == 0) request.method = NOA_METHOD_HEAD;
    else if (strcmp(method, "POST")    == 0) request.method = NOA_METHOD_POST;
    else if (strcmp(method, "PUT")     == 0) request.method = NOA_METHOD_PUT;
    else if (strcmp(method, "DELETE")  == 0) request.method = NOA_METHOD_DELETE;
    else if (strcmp(method, "CONNECT") == 0) request.method = NOA_METHOD_CONNECT;
    else if (strcmp(method, "OPTIONS") == 0) request.method = NOA_METHOD_OPTIONS;
    else if (strcmp(method, "TRACE")   == 0) request.method = NOA_METHOD_TRACE;
    else                                     request.method = NOA_METHOD_UNKNOWN;

    // Target resource
    // It is RECOMMENDED that all senders and recipients support, at a minimum, URIs with lengths of 8000 octets in protocol elements.
    static char path[MEGABYTES(8)];

    // TODO: Respond with request url too long if required
    i = next_non_whitespace_index(buf, buf_size, i);
    u32 j = 0;
    for (; i < buf_size && j < MEGABYTES(8) - 1 && !isspace(buf[i]); ++i, ++j) {
        path[j] = buf[i];
    }

    path[j] = 0;

    request.path = PUSH_ARRAY(arena, char, j + 1);
    strcpy(request.path, path);

    // Version
    i = next_non_whitespace_index(buf, buf_size, i);

    // TODO: Respond 400?
#define ASSERT_NEXT_CHAR(CHAR)     \
    do {                           \
        if (buf[i++] != CHAR) {    \
            request.valid = false; \
            return request;        \
        }                          \
    } while (0)

    ASSERT_NEXT_CHAR('H');
    ASSERT_NEXT_CHAR('T');
    ASSERT_NEXT_CHAR('T');
    ASSERT_NEXT_CHAR('P');
    ASSERT_NEXT_CHAR('/');

    request.version_major = buf[i++] - '0';
    if (buf[i] == '\r') {
        // When a major version of HTTP does not define any minor versions, the minor version "0" is implied.
        // The "0" is used when referring to that protocol within elements that require a minor version identifier.
        request.version_minor = 0;
    } else {
        ASSERT_NEXT_CHAR('.');
        request.version_minor = buf[i++] - '0';
    }

    ASSERT_NEXT_CHAR('\r');
    ASSERT_NEXT_CHAR('\n');

    request.headers      = PUSH_ARRAY(arena, NoaHeader, NOA_MAX_FIELDS);
    request.header_count = 0;
    while (request.header_count < NOA_MAX_FIELDS) {
        NoaHeader header;
        if (isspace(buf[i]))
            break;

        usize name_begin = i;
        for (; i < buf_size; ++i) {
            if (!is_tchar(buf[i]) && buf[i] != ':') {
                NOA_ERROR("HTTP header parse failed: field name has unexpected character: %c", buf[i]);
                request.valid = false;
                return request;
            } else if (buf[i] == ':') {
                usize name_length = i - name_begin;
                header.name       = PUSH_ARRAY(arena, char, name_length + 1);
                memcpy(header.name, &buf[name_begin], name_length);
                header.name[name_length] = 0;

                break;
            }
        }

        ASSERT_NEXT_CHAR(':');
        i = next_non_whitespace_index(buf, buf_size, i);

        usize value_begin = i;
        for (; i < buf_size && buf[i] != '\r'; ++i);
        usize value_length = i - value_begin;
        header.value       = PUSH_ARRAY(arena, char, value_length + 1);
        memcpy(header.value, &buf[value_begin], value_length);
        header.value[value_length] = 0;

        ASSERT_NEXT_CHAR('\r');
        ASSERT_NEXT_CHAR('\n');

        request.headers[request.header_count++] = header;
    }

    ASSERT_NEXT_CHAR('\r');
    ASSERT_NEXT_CHAR('\n');

    if (i < buf_size) {
        usize data_begin = i;
        NOA_INFO("Additional data detected");
        for (; i < buf_size; ++i);
        usize data_size   = i - data_begin;
        request.data      = PUSH_ARRAY(arena, char, data_size);
        request.data_size = data_size;
        memcpy(request.data, &buf[data_begin], data_size);
    }

#undef ASSERT_NEXT_CHAR

    request.valid = true;
    return request;
}

#define NOA_MAX_WEBSOCKET_PAYLOAD_LENGTH MEGABYTES(16)

static NoaWebsocketMessage parse_websocket_message(u8 *buf, usize buf_size) {
    NoaWebsocketMessage message = {0};
    usize i = 0;

#define VERIFY_BUFFER_BOUNDS(REQUESTED_BYTES)                 \
    do {                                                      \
        if (i + REQUESTED_BYTES > buf_size) {                 \
            NOA_ERROR("unexpected end of websocket message"); \
            message.valid = false;                            \
            return message;                                   \
        }                                                     \
    } while (0)

    VERIFY_BUFFER_BOUNDS(1);
    u8 first_byte = buf[i++];

    message.fin    = first_byte & 0b10000000;
    message.rsv1   = first_byte & 0b01000000;
    message.rsv2   = first_byte & 0b00100000;
    message.rsv3   = first_byte & 0b00010000;
    message.opcode = first_byte & 0b00001111;

    /*
        RSV1, RSV2, RSV3:  1 bit each

        MUST be 0 unless an extension is negotiated that defines meanings
        for non-zero values.  If a nonzero value is received and none of
        the negotiated extensions defines the meaning of such a nonzero
        value, the receiving endpoint MUST fail the WebSocket
        connection.
    */
    if (message.rsv1 != 0 || message.rsv2 != 0 || message.rsv3 != 0) {
        message.valid = false;
        return message;
    }

    VERIFY_BUFFER_BOUNDS(1);
    u8 masked                 = buf[i] & 0b10000000;
    u8 payload_length_control = buf[i] & 0b01111111;

    // NOTE: Multibyte length quantities are expressed in network byte order.
    if (payload_length_control == 126) {
        VERIFY_BUFFER_BOUNDS(3);
        message.payload_length = ((u64) buf[i + 2]) | ((u64) buf[i + 1] << 8);
        i += 3;
    } else if (payload_length_control == 127) {
        VERIFY_BUFFER_BOUNDS(9);
        message.payload_length = buf[i + 8] | (buf[i + 7] << 8) | (buf[i + 6] << 16) | (buf[i + 5] << 24) |
                                 ((u64) buf[i + 4] << 32) | ((u64) buf[i + 3] << 40) | ((u64) buf[i + 2] << 48) | ((u64) buf[i + 1] << 56);
        i += 9;
    } else {
        message.payload_length = payload_length_control;
        ++i;
    }

    u8 mask_key[4] = {0};
    if (masked) {
        VERIFY_BUFFER_BOUNDS(4);
        memcpy(mask_key, &buf[i], 4);
        i += 4;
    }

    NOA_INFO("mask key: %x %x %x %x", mask_key[0], mask_key[1], mask_key[2], mask_key[3]);

    if (message.payload_length > NOA_MAX_WEBSOCKET_PAYLOAD_LENGTH) {
        message.valid = false;
        return message;
    }

    message.payload = malloc(message.payload_length);
    memset(message.payload, 69, message.payload_length);
    VERIFY_BUFFER_BOUNDS(message.payload_length);

    if (masked) {
        for (u64 j = 0; j < message.payload_length && i < buf_size; ++j, ++i) {
            message.payload[j] = buf[i] ^ mask_key[j % 4];
        }
    } else {
        memcpy(message.payload, &buf[i], message.payload_length);
    }

#undef VERIFY_BUFFER_BOUNDS

    message.valid = true;
    return message;
}

void noa_return_websocket_message(NoaWebsocketMessage *message) {
    if (message->payload) {
        free(message->payload);
    }
}

#define NOA_MAX_CONNECTIONS 128
#define NOA_KEEP_ALIVE_TIMEOUT 5
#define NOA_WEBSOCKET_TIMEOUT 30
#define NOA_KEEP_ALIVE_MAX_REQUESTS 100

static Listener listener;
static NoaConnection global_connections[NOA_MAX_CONNECTIONS]      = {0};
static PlatformPollfd global_connection_pfds[NOA_MAX_CONNECTIONS] = {0};
static u32 global_connection_count = 0;
static u64 global_next_connection_uid = 1;

void noa_init(const char *address, u16 port) {
    listener = platform_init_listener(address, port);
    NOA_INFO("Noa listening on port %d", port);

    for (u32 i = 0; i < NOA_MAX_CONNECTIONS; ++i) {
        global_connections[i].fd = PLATFORM_INVALID_SOCKET;
    }
}

static void close_and_cleanup(NoaConnection *connection) {
    platform_close(connection->fd);
    connection->fd = PLATFORM_INVALID_SOCKET;
    platform_invalidate_pollfd(&global_connection_pfds[connection->id]);
    --global_connection_count;
}

i32 noa_must_process_connections(void) {
    i32 ret = false;
    // Accept any new connections
    if (platform_found_connections(&listener)) {
        NoaConnection connection = {0};
        connection.fd                    = platform_accept(&listener);
        connection.last_active_timestamp = time(null);
        connection.remaining_requests    = NOA_KEEP_ALIVE_MAX_REQUESTS;
        connection.has_data              = false;

        NOA_INFO("accepted new connection.");

        if (global_connection_count >= NOA_MAX_CONNECTIONS) {
            NOA_ERROR("too many connections! dropping newly accepted connection.");
            platform_close(connection.fd);
        } else {
            for (u32 i = 0; i < NOA_MAX_CONNECTIONS; ++i) {
                if (global_connections[i].fd == PLATFORM_INVALID_SOCKET) {
                    connection.id             = i;
                    connection.uid            = global_next_connection_uid++;
                    global_connections[i]     = connection;
                    global_connection_pfds[i] = platform_create_pollfd(connection.fd);
                    ++global_connection_count;
                    break;
                }
            }
        }
    }

    // Check if any connections have data for us, and check if any have timed out
    i64 now = time(null);

    for (u32 i = 0; i < NOA_MAX_CONNECTIONS; ++i) {
        if (global_connections[i].fd != PLATFORM_INVALID_SOCKET) {
            if (global_connections[i].is_websocket) {
                if (now - global_connections[i].last_active_timestamp > NOA_WEBSOCKET_TIMEOUT / 2 && !global_connections[i].is_waiting_for_pong) {
                    NoaWebsocketMessage m = {0};
                    m.fin = 1;
                    m.opcode = NOA_WS_OPCODE_PING;
                    if (!noa_websocket_send(&global_connections[i], &m)) {
                        NOA_ERROR("failed to ping websocket- assuming it's dead. goodbye!");
                        close_and_cleanup(&global_connections[i]);
                    } else {
                        NOA_INFO("ping! are you there socket " SOCKET_FMT "?", global_connections[i].fd);
                        global_connections[i].is_waiting_for_pong = true;
                    }
                } else if (now - global_connections[i].last_active_timestamp > NOA_WEBSOCKET_TIMEOUT) {
                    NOA_INFO("websocket connection with fd=" SOCKET_FMT " has timed out. goodbye!", global_connections[i].fd);
                    close_and_cleanup(&global_connections[i]);
                }
            } else {
                if (now - global_connections[i].last_active_timestamp > NOA_KEEP_ALIVE_TIMEOUT) {
                    NOA_INFO("connection with fd=" SOCKET_FMT " has timed out. it was last active at %lld, but the time is currently %lld", global_connections[i].fd, global_connections[i].last_active_timestamp, now);
                    close_and_cleanup(&global_connections[i]);
                } else if (global_connections[i].remaining_requests == 0) {
                    NOA_INFO("connection with fd=" SOCKET_FMT "has used up all available requests.", global_connections[i].fd);
                    close_and_cleanup(&global_connections[i]);
                }
            }
        }
    }

    ret = platform_poll(global_connection_pfds, NOA_MAX_CONNECTIONS, 0) > 0;
    if (ret) {
        for (u32 i = 0; i < NOA_MAX_CONNECTIONS; ++i) {
            global_connections[i].has_data = platform_socket_pfd_has_data(global_connection_pfds[i]);
        }
    }

    return ret;
}

i32 noa_receive_request(NoaConnection *connection, NoaRequest *request) {
    memset(request, 0, sizeof(NoaRequest));
    memset(recv_buffer, 0, sizeof(recv_buffer));
    isize bytes = platform_recv(connection->fd, (u8 *) recv_buffer, sizeof(recv_buffer), 0);
    if (bytes == PLATFORM_RECV_ERROR) {
        NOA_ERROR("recv failed.");
        // platform_close(fd);
        return false;
    }

    NOA_INFO("(recv) received %lld bytes:\n%s", bytes, recv_buffer);
    NoaRequest parsed_request = parse_http_request(recv_buffer, bytes);

    if (parsed_request.version_major != 1) {
        NOA_ERROR("unsupported HTTP version");
        // platform_close(fd);
        return false;
    }

    connection->is_keep_alive = true;

    if (parsed_request.version_minor == 0) {
        NOA_INFO("HTTP 1.0 detected. defaulting to no keep-alive");
        connection->is_keep_alive = false;
    }

    i32 connection_upgrade = false;
    i32 upgrade_websocket  = false;
    for (u32 i = 0; i < parsed_request.header_count; ++i) {
        if (str_equal_case_insensitive(parsed_request.headers[i].name, "Connection")) {
            if (str_equal_case_insensitive(parsed_request.headers[i].value, "close")) {
                connection->is_keep_alive = false;
            } else if (str_equal_case_insensitive(parsed_request.headers[i].value, "upgrade")) {
                connection_upgrade = true;
            } else {
                connection->is_keep_alive = true;
            }
        } else if (str_equal_case_insensitive(parsed_request.headers[i].name, "Upgrade") && str_equal_case_insensitive(parsed_request.headers[i].value, "websocket")) {
            upgrade_websocket = true;
        } else if (str_equal_case_insensitive(parsed_request.headers[i].name, "Sec-WebSocket-Key")) {
            parsed_request.websocket_key = PUSH_ARRAY(arena, char, strlen(parsed_request.headers[i].value) + 1);
            strcpy(parsed_request.websocket_key, parsed_request.headers[i].value);
        } else if (str_equal_case_insensitive(parsed_request.headers[i].name, "Sec-WebSocket-Version")) {
            parsed_request.websocket_version = atoi(parsed_request.headers[i].value);
        }
    }

    parsed_request.websocket_upgrade_requested = connection_upgrade && upgrade_websocket;

    if (!connection->is_keep_alive && !parsed_request.websocket_upgrade_requested)
        connection->remaining_requests = 1;

    memcpy(request, &parsed_request, sizeof(NoaRequest));
    connection->last_active_timestamp = time(null);
    --connection->remaining_requests;
    connection->has_data = false;

    return true;
}

NoaConnection *noa_next_client(void) {
    for (u32 i = 0; i < NOA_MAX_CONNECTIONS; ++i) {
        if (global_connections[i].has_data) {
            return &global_connections[i];
        }
    }

    return null;
}

NoaConnection *noa_get_connection(u64 uid) {
    if (uid == 0) {
        return null;
    }

    for (u32 i = 0; i < NOA_MAX_CONNECTIONS; ++i) {
        if (global_connections[i].uid == uid)
            return &global_connections[i];
    }

    return null;
}

void noa_respond(NoaConnection *connection, NoaResponse *response) {
    StringBuffer sb = noa_sb_create(KILOBYTES(4));
    time_t t        = time(null);
    struct tm *gm   = gmtime(&t);
    char date_buf[64];

    strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT", gm);

    usize bytes_to_send = 0;
    bytes_to_send += noa_sb_append_cstr(&sb, "HTTP/1.1 ");
    bytes_to_send += noa_sb_append_u32 (&sb, response->status_code);
    bytes_to_send += noa_sb_append_byte(&sb, ' ');
    bytes_to_send += noa_sb_append_cstr(&sb, response->status_message);
    bytes_to_send += noa_sb_append_cstr(&sb, "\r\nDate: ");
    bytes_to_send += noa_sb_append_cstr(&sb, date_buf);
    bytes_to_send += noa_sb_append_cstr(&sb, "\r\nServer: Noa/0.0.1\r\nContent-Length: ");
    bytes_to_send += noa_sb_append_u32 (&sb, response->data_size);
    bytes_to_send += noa_sb_append_cstr(&sb, "\r\n");

    // This request is currently upgrading to websockets
    if (connection->is_websocket) {
        bytes_to_send += noa_sb_append_cstr(&sb, "Connection: Upgrade\r\n");
    } else if (connection->is_keep_alive) {
        bytes_to_send += noa_sb_append_cstr(&sb, "Connection: keep-alive\r\nKeep-Alive: timeout=");
        bytes_to_send += noa_sb_append_u32 (&sb, NOA_KEEP_ALIVE_TIMEOUT);
        bytes_to_send += noa_sb_append_cstr(&sb, ", max=");
        bytes_to_send += noa_sb_append_u32 (&sb, NOA_KEEP_ALIVE_MAX_REQUESTS);
        bytes_to_send += noa_sb_append_cstr(&sb, "\r\n");
    } else {
        bytes_to_send += noa_sb_append_cstr(&sb, "Connection: close\r\n");
    }

    for (u32 i = 0; i < response->header_count; ++i) {
        bytes_to_send += noa_sb_append_cstr(&sb, response->headers[i].name);
        bytes_to_send += noa_sb_append_cstr(&sb, ": ");
        bytes_to_send += noa_sb_append_cstr(&sb, response->headers[i].value);
        bytes_to_send += noa_sb_append_cstr(&sb, "\r\n");
    }

    bytes_to_send += noa_sb_append_cstr(&sb, "\r\n");
    i32 bytes_sent = platform_send(connection->fd, (u8 *) sb.data, bytes_to_send);
    if (bytes_sent == PLATFORM_SOCKET_ERROR) {
        NOA_ERROR("Socket error when sending message");
    } else {
        NOA_INFO("Sent %d bytes to the client", bytes_sent);
    }

    if (response->data_size > 0) {
        bytes_sent = platform_send(connection->fd, (u8 *) response->data, response->data_size);
        if (bytes_sent == PLATFORM_SOCKET_ERROR) {
            NOA_ERROR("socket error when sending data");
        } else {
            NOA_INFO("(data) sent %d bytes to the client", bytes_sent);
        }
    }

    noa_sb_delete(&sb);
}

i32 noa_websocket_send(NoaConnection *connection, NoaWebsocketMessage *message) {
    assert(connection->is_websocket);
    u8 header_size = 2;
    u8 bytes[10] = {0};

    if (message->fin)  bytes[0] |= 0b10000000;
    if (message->rsv1) bytes[0] |= 0b01000000;
    if (message->rsv2) bytes[0] |= 0b00100000;
    if (message->rsv3) bytes[0] |= 0b00010000;

    bytes[0] |= (u8) message->opcode;


    if      (message->payload_length > UINT16_MAX) bytes[1] = 127;
    else if (message->payload_length > 125)        bytes[1] = 126;
    else                                           bytes[1] = message->payload_length;

    if (bytes[1] == 126) {
        bytes[2] = (message->payload_length & 0xFF00) >> 8;
        bytes[3] = message->payload_length & 0xFF;
        header_size = 4;
    } else if (bytes[1] == 127) {
        bytes[2] = (message->payload_length & 0xFF00000000000000) >> 56;
        bytes[3] = (message->payload_length & 0xFF000000000000)   >> 48;
        bytes[4] = (message->payload_length & 0xFF0000000000)     >> 40;
        bytes[5] = (message->payload_length & 0xFF00000000)       >> 32;
        bytes[6] = (message->payload_length & 0xFF000000)         >> 24;
        bytes[7] = (message->payload_length & 0xFF0000)           >> 16;
        bytes[8] = (message->payload_length & 0xFF00)             >> 8;
        bytes[9] = (message->payload_length & 0xFF);
        header_size = 10;
    }

    i32 bytes_sent = platform_send(connection->fd, (u8 *) bytes, header_size);
    if (bytes_sent == PLATFORM_SOCKET_ERROR) {
        NOA_ERROR("(websocket header) socket error when sending data");
        return false;
    } else {
        NOA_INFO("(websocket header) sent %d bytes to the client", bytes_sent);
    }

    bytes_sent = platform_send(connection->fd, message->payload, message->payload_length);
    if (bytes_sent == PLATFORM_SOCKET_ERROR) {
        NOA_ERROR("(websocket payload) socket error when sending data");
        return false;
    } else {
        NOA_INFO("(websocket payload) sent %d bytes to the client", bytes_sent);
    }

    return true;
}

#define WEBSOCKET_MAGIC "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
void noa_upgrade_connection(NoaConnection *connection, NoaRequest *request) {
    assert(request->websocket_upgrade_requested);

    StringBuffer sb = noa_sb_create(512);
    u32 size = 0;
    size += noa_sb_append_cstr(&sb, request->websocket_key);
    size += noa_sb_append_cstr(&sb, WEBSOCKET_MAGIC);

    u8 result[20];

    SHA1((char *) result, sb.data, size);
    StringBuffer b64 = noa_base64_encode((u8 *) result, 20);

    noa_sb_append_byte(&b64, 0);
    NOA_INFO("Calculated accept hash: %s", b64.data);

    NoaHeader headers[] = {
        (NoaHeader) {"Upgrade", "websocket"},
        (NoaHeader) {"Sec-WebSocket-Accept", b64.data},
        (NoaHeader) {"Sec-WebSocket-Version", "13"},
    };

    connection->is_websocket = true;

    NoaResponse response    = {0};
    response.status_code    = NOA_STATUS_SWITCHING_PROTOCOLS;
    response.status_message = NOA_STATUS_SWITCHING_PROTOCOLS_MSG;
    response.headers        = headers;
    response.header_count   = ARRAY_LEN(headers);

    noa_respond(connection, &response);

    noa_sb_delete(&b64);
    noa_sb_delete(&sb);
}

i32 noa_receive_websocket_message(NoaConnection *connection, NoaWebsocketMessage *message) {
    memset(message, 0, sizeof(NoaWebsocketMessage));
    memset(recv_buffer, 0, sizeof(recv_buffer));
    isize bytes = platform_recv(connection->fd, (u8 *) recv_buffer, sizeof(recv_buffer), 0);
    if (bytes == PLATFORM_RECV_ERROR) {
        NOA_ERROR("recv failed.");
        // platform_close(fd);
        return false;
    }

    NOA_INFO("(recv) received %lld byte long websocket message", bytes);
    NoaWebsocketMessage parsed_message = parse_websocket_message((u8 *) recv_buffer, bytes);
    NOA_INFO("message is valid? %d", parsed_message.valid);

    if (connection->is_waiting_for_pong && parsed_message.valid && parsed_message.opcode == NOA_WS_OPCODE_PONG) {
        NOA_INFO("pong from socket " SOCKET_FMT ". keeping it alive.", connection->fd);
        connection->is_waiting_for_pong = false;
    }

    memcpy(message, &parsed_message, sizeof(NoaWebsocketMessage));
    connection->last_active_timestamp = time(null);
    return true;
}

void noa_websocket_close(NoaConnection *connection) {
    NOA_INFO("closing websocket connection with fd=" SOCKET_FMT ". goodbye!", connection->fd);
    close_and_cleanup(connection);
}
