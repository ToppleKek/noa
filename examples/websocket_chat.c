/**
    Noa HTTP server.
    **NOA EXAMPLE PROGRAM**
    WebSocket chat server.

    Author: Braeden Hong
    Date:   2024/10/31
*/
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "../noa.h"

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

#define ARRAY_LEN(ARR) (sizeof(ARR) / sizeof(ARR[0]))
#define NOA_EXAMPLE_MAX_USERS 64
#define NOA_EXAMPLE_MAX_USERNAME_LEN 64
typedef struct {
    char *data;
    size_t size;
} NoaExampleFile;

typedef struct {
    u64 connection_uid;
    char name[NOA_EXAMPLE_MAX_USERNAME_LEN];
    u32 name_len;
} NoaChatUser;

static NoaChatUser users[NOA_EXAMPLE_MAX_USERS] = {0};
static u32 connected_users                      = 0;

NoaChatUser *get_user_by_uid(u64 connection_uid) {
    for (u32 i = 0; i < NOA_EXAMPLE_MAX_USERS; ++i) {
        if (users[i].connection_uid == connection_uid) {
            return &users[i];
        }
    }

    return null;
}

i32 add_user(u64 connection_uid, char *name, u32 name_len) {
    if (name_len > NOA_EXAMPLE_MAX_USERNAME_LEN) {
        return false;
    }

    for (u32 i = 0; i < NOA_EXAMPLE_MAX_USERS; ++i) {
        if (users[i].connection_uid == 0) {
            users[i].connection_uid = connection_uid;
            users[i].name_len       = name_len;
            memcpy(users[i].name, name, name_len);
            return true;
        }
    }

    return false;
}

NoaExampleFile read_entire_file(const char *path) {
    FILE *f = fopen(path, "rb");
    assert(f);

    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *file_data = malloc(file_size);
    assert(file_data);

    fread(file_data, 1, file_size, f);
    fclose(f);

    return (NoaExampleFile) {file_data, file_size};
}

static char msg_buffer[16 * 1024];

static void broadcast_message(char *message, usize message_size) {
    NoaWebsocketMessage response_message = {0};
    response_message.fin                 = 1;
    response_message.opcode              = NOA_WS_OPCODE_TEXT;
    response_message.payload_length      = message_size;
    response_message.payload             = (u8 *) message;

    for (int i = 0; i < NOA_EXAMPLE_MAX_USERS; ++i) {
        NoaConnection *c = noa_get_connection(users[i].connection_uid);
        if (c) {
            noa_websocket_send(c, &response_message);
        }
    }
}

int main(void) {
    NoaExampleFile index_html = read_entire_file("chat.html");
    NoaExampleFile noa_webp   = read_entire_file("noa.webp");

    noa_init("0.0.0.0", 8080);

    for (;;) {
        if (noa_must_process_connections()) {
            NoaConnection *connection = noa_next_client();
            NoaRequest request;

            if (connection && connection->is_websocket) {
                NoaWebsocketMessage message;
                noa_receive_websocket_message(connection, &message);

                if (message.opcode == NOA_WS_OPCODE_TEXT) {
                    NoaChatUser *user = get_user_by_uid(connection->uid);
                    if (!user) {
                        if (!add_user(connection->uid, (char *) message.payload, message.payload_length)) {
                            printf("Failed to add a new user.\n");
                            noa_websocket_close(connection);
                            continue;
                        }

                        strcpy(msg_buffer, "System Message: New user: ");
                        strncat(msg_buffer, message.payload, message.payload_length);

                        broadcast_message(msg_buffer, strlen(msg_buffer));
                    } else {
                        if (message.payload_length + 64 > ARRAY_LEN(msg_buffer)) {
                            noa_websocket_close(connection);
                            continue;
                        }

                        memcpy(msg_buffer, user->name, user->name_len);
                        msg_buffer[user->name_len]     = ':';
                        msg_buffer[user->name_len + 1] = ' ';
                        memcpy(msg_buffer + user->name_len + 2, message.payload, message.payload_length);
                        broadcast_message(msg_buffer, user->name_len + 2 + message.payload_length);
                    }
                } else if (message.opcode == NOA_WS_OPCODE_CLOSE) {
                    NoaChatUser *user = get_user_by_uid(connection->uid);
                    if (user) {
                        user->connection_uid = 0;
                    }

                    NoaWebsocketMessage response_message = {0};
                    response_message.fin                 = 1;
                    response_message.opcode              = NOA_WS_OPCODE_CLOSE;
                    noa_websocket_send(connection, &response_message);

                    noa_websocket_close(connection);
                }

                noa_return_websocket_message(&message);
            } else if (connection && noa_receive_request(connection, &request)) {
               if (!request.valid) {
                    printf("Got an invalid HTTP request!\n");
                    continue;
                }

                if (request.websocket_upgrade_requested) {
                    printf("request is looking to upgrade\n");
                    noa_upgrade_connection(connection, &request);
                    continue;
                }

                NoaResponse response = {0};
                NoaHeader headers[1];

                if (request.method != NOA_METHOD_GET) {
                    response.status_code    = NOA_STATUS_METHOD_NOT_ALLOWED;
                    response.status_message = NOA_STATUS_METHOD_NOT_ALLOWED_MSG;
                } else if (strcmp(request.path, "/") == 0) {
                    headers[0] = (NoaHeader) {"Content-Type", "text/html; charset=utf-8"};

                    response.status_code    = NOA_STATUS_OK;
                    response.status_message = NOA_STATUS_OK_MSG;
                    response.data           = index_html.data;
                    response.data_size      = index_html.size;
                    response.headers        = (NoaHeader *) headers;
                    response.header_count   = ARRAY_LEN(headers);
                } else if (strcmp(request.path, "/noa.webp") == 0) {
                    headers[0] = (NoaHeader) {"Content-Type", "image/webp"};

                    response.status_code    = NOA_STATUS_OK;
                    response.status_message = NOA_STATUS_OK_MSG;
                    response.data           = noa_webp.data;
                    response.data_size      = noa_webp.size;
                    response.headers        = (NoaHeader *) headers;
                    response.header_count   = ARRAY_LEN(headers);
                } else {
                    response.status_code    = NOA_STATUS_NOT_FOUND;
                    response.status_message = NOA_STATUS_NOT_FOUND_MSG;
                }

                noa_respond(connection, &response);
            }
        }
    }
}
