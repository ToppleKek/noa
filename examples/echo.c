/**
    Noa HTTP server.
    **NOA EXAMPLE PROGRAM**
    Simple echo server. This application echos back whatever data was POSTed to it.

    Author: Braeden Hong
    Date:   2024/10/31
*/

#include <stdio.h>
#include "../noa.h"

int main(void) {
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

                if (request.method != NOA_METHOD_POST) {
                    printf("Invalid request method.\n");
                    response.status_code    = NOA_STATUS_METHOD_NOT_ALLOWED;
                    response.status_message = NOA_STATUS_METHOD_NOT_ALLOWED_MSG;
                } else if (request.data_size == 0) {
                    printf("No data to echo.\n");
                    response.status_code    = NOA_STATUS_BAD_REQUEST;
                    response.status_message = NOA_STATUS_BAD_REQUEST_MSG;
                } else {
                    response.status_code    = NOA_STATUS_OK;
                    response.status_message = NOA_STATUS_OK_MSG;
                    response.data           = request.data;
                    response.data_size      = request.data_size;
                }

                noa_respond(connection, &response);
            }
        }
    }

    return 0;
}