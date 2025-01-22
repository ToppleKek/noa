/**
    Noa HTTP server.
    **NOA EXAMPLE PROGRAM**
    Basic web server example. Sends a simple HTML document, "index.html", to all GET requests to the resource "/".

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
    NoaExampleFile index_html = read_entire_file("index.html");
    NoaExampleFile image      = read_entire_file("image.jpg");
    NoaExampleFile image2     = read_entire_file("image2.jpg");

    noa_init("0.0.0.0", 8080);

    for (;;) {
        if (noa_must_process_connections()) {
            NoaConnection *connection = noa_next_client();
            NoaRequest request;
            if (connection && noa_receive_request(connection, &request)) {
                if (!request.valid) {
                    printf("Got an invalid HTTP request!\n");
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
                } else if (strcmp(request.path, "/image.jpg") == 0) {
                    headers[0] = (NoaHeader) {"Content-Type", "image/jpeg"};

                    response.status_code    = NOA_STATUS_OK;
                    response.status_message = NOA_STATUS_OK_MSG;
                    response.data           = image.data;
                    response.data_size      = image.size;
                    response.headers        = (NoaHeader *) headers;
                    response.header_count   = ARRAY_LEN(headers);
                } else if (strcmp(request.path, "/image2.jpg") == 0) {
                    headers[0] = (NoaHeader) {"Content-Type", "image/jpeg"};

                    response.status_code    = NOA_STATUS_OK;
                    response.status_message = NOA_STATUS_OK_MSG;
                    response.data           = image2.data;
                    response.data_size      = image2.size;
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

    free(index_html.data);
    free(image.data);
    free(image2.data);
}
