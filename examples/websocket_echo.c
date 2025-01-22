/**
    Noa HTTP server.
    **NOA EXAMPLE PROGRAM**
    Websocket echo server.

    Author: Braeden Hong
    Date:   2024/10/31
*/
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../noa.h"

#define ARRAY_LEN(ARR) (sizeof(ARR) / sizeof(ARR[0]))

typedef struct {
    char *data;
    size_t size;
} NoaExampleFile;

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

int main(void) {
    NoaExampleFile index = read_entire_file("websocket_echo.html");
    noa_init("0.0.0.0", 8080);

    for (;;) {
        if (noa_must_process_connections()) {
            NoaConnection *connection = noa_next_client();
            NoaRequest request;

            if (connection && connection->is_websocket) {
                NoaWebsocketMessage message;
                noa_receive_websocket_message(connection, &message);
                printf("Received a websocket message!\nfin=%d opcode=%d payload_length=%llu\n\n", message.fin, message.opcode, message.payload_length);
                for (int i = 0; i < message.payload_length; ++i) {
                    putchar(message.payload[i]);
                }
                putchar('\n');

                if (message.opcode == NOA_WS_OPCODE_TEXT) {
                    NoaWebsocketMessage response_message = {0};
                    response_message.fin                 = 1;
                    response_message.opcode              = NOA_WS_OPCODE_TEXT;
                    response_message.payload_length      = message.payload_length;
                    response_message.payload             = message.payload;
                    noa_websocket_send(connection, &response_message);
                } else if (message.opcode == NOA_WS_OPCODE_CLOSE) {
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
                NoaHeader header;
                if (strcmp(request.path, "/") == 0) {
                    header = (NoaHeader) {"Content-Type", "text/html; charset=utf-8"};

                    response.status_code    = NOA_STATUS_OK;
                    response.status_message = NOA_STATUS_OK_MSG;
                    response.data           = index.data;
                    response.data_size      = index.size;
                    response.headers        = &header;
                    response.header_count   = 1;
                } else {
                    response.status_code    = NOA_STATUS_NOT_FOUND;
                    response.status_message = NOA_STATUS_NOT_FOUND_MSG;
                }

                noa_respond(connection, &response);
            }
        }
    }
}
