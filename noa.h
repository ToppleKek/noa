/**
    Noa HTTP 1.1/WebSocket 13 server.

    Author: Braeden Hong
    Date:   2024/10/31
*/

#ifndef _NOA_H_
#define _NOA_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define PLATFORM_INVALID_SOCKET INVALID_SOCKET
#define PLATFORM_SOCKET_ERROR SOCKET_ERROR
#define PLATFORM_RECV_ERROR -1

typedef SOCKET PlatformSocket;
#elif defined(unix)
#define PLATFORM_INVALID_SOCKET -1
#define PLATFORM_SOCKET_ERROR -1
#define PLATFORM_RECV_ERROR -1

typedef int PlatformSocket;
#else
#error Unsupported platform
#endif

typedef enum {
    NOA_METHOD_UNKNOWN,
    NOA_METHOD_GET,
    NOA_METHOD_HEAD,
    NOA_METHOD_POST,
    NOA_METHOD_PUT,
    NOA_METHOD_DELETE,
    NOA_METHOD_CONNECT,
    NOA_METHOD_OPTIONS,
    NOA_METHOD_TRACE,
} NoaMethod;

#define NOA_STATUS_CONTINUE                        100
#define NOA_STATUS_SWITCHING_PROTOCOLS             101
#define NOA_STATUS_EARLY_HINTS                     103

#define NOA_STATUS_OK                              200
#define NOA_STATUS_CREATED                         201
#define NOA_STATUS_ACCEPTED                        202
#define NOA_STATUS_NON_AUTHORITATIVE_INFORMATION   203
#define NOA_STATUS_NO_CONTENT                      204
#define NOA_STATUS_RESET_CONTENT                   205
#define NOA_STATUS_PARTIAL_CONTENT                 206
#define NOA_STATUS_IM_USED                         226

#define NOA_STATUS_BAD_REQUEST                     400
#define NOA_STATUS_UNAUTHORIZED                    401
#define NOA_STATUS_FORBIDDEN                       403
#define NOA_STATUS_NOT_FOUND                       404
#define NOA_STATUS_METHOD_NOT_ALLOWED              405
#define NOA_STATUS_NOT_ACCEPTABLE                  406
#define NOA_STATUS_PROXY_AUTHENTICATION_REQUIRED   407
#define NOA_STATUS_REQUEST_TIMEOUT                 408
#define NOA_STATUS_CONFLICT                        409
#define NOA_STATUS_GONE                            410
#define NOA_STATUS_LENGTH_REQUIRED                 411
#define NOA_STATUS_PRECONDITION_FAILED             412
#define NOA_STATUS_PAYLOAD_TOO_LARGE               413
#define NOA_STATUS_URI_TOO_LONG                    414
#define NOA_STATUS_UNSUPPORTED_MEDIA_TYPE          415
#define NOA_STATUS_RANGE_NOT_SATISFIABLE           416
#define NOA_STATUS_EXPECTATION_FAILED              417
#define NOA_STATUS_IM_A_TEAPOT                     418
#define NOA_STATUS_MISDIRECTED_REQUEST             421
#define NOA_STATUS_UNPROCESSABLE_CONTENT           422
#define NOA_STATUS_LOCKED                          423
#define NOA_STATUS_FAILED_DEPENDENCY               424
#define NOA_STATUS_TOO_EARLY                       425
#define NOA_STATUS_UPGRADE_REQUIRED                426
#define NOA_STATUS_PRECONDITION_REQUIRED           428
#define NOA_STATUS_TOO_MANY_REQUESTS               429
#define NOA_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE 431
#define NOA_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS   451

#define NOA_STATUS_CONTINUE_MSG                        "Continue"
#define NOA_STATUS_SWITCHING_PROTOCOLS_MSG             "Switching Protocols"
#define NOA_STATUS_EARLY_HINTS_MSG                     "Early Hints"

#define NOA_STATUS_OK_MSG                              "OK"
#define NOA_STATUS_CREATED_MSG                         "Created"
#define NOA_STATUS_ACCEPTED_MSG                        "Accepted"
#define NOA_STATUS_NON_AUTHORITATIVE_INFORMATION_MSG   "Non-Authoritative Information"
#define NOA_STATUS_NO_CONTENT_MSG                      "No Content"
#define NOA_STATUS_RESET_CONTENT_MSG                   "Reset Content"
#define NOA_STATUS_PARTIAL_CONTENT_MSG                 "Partial Content"
#define NOA_STATUS_IM_USED_MSG                         "IM Used"

#define NOA_STATUS_BAD_REQUEST_MSG                     "Bad Request"
#define NOA_STATUS_UNAUTHORIZED_MSG                    "Unauthorized"
#define NOA_STATUS_FORBIDDEN_MSG                       "Forbidden"
#define NOA_STATUS_NOT_FOUND_MSG                       "Not Found"
#define NOA_STATUS_METHOD_NOT_ALLOWED_MSG              "Method Not Allowed"
#define NOA_STATUS_NOT_ACCEPTABLE_MSG                  "Not Acceptable"
#define NOA_STATUS_PROXY_AUTHENTICATION_REQUIRED_MSG   "Proxy Authentication Required"
#define NOA_STATUS_REQUEST_TIMEOUT_MSG                 "Request Timeout"
#define NOA_STATUS_CONFLICT_MSG                        "Conflict"
#define NOA_STATUS_GONE_MSG                            "Gone"
#define NOA_STATUS_LENGTH_REQUIRED_MSG                 "Length Required"
#define NOA_STATUS_PRECONDITION_FAILED_MSG             "Precondition Failed"
#define NOA_STATUS_PAYLOAD_TOO_LARGE_MSG               "Payload Too Large"
#define NOA_STATUS_URI_TOO_LONG_MSG                    "URI Too Long"
#define NOA_STATUS_UNSUPPORTED_MEDIA_TYPE_MSG          "Unsupported Media Type"
#define NOA_STATUS_RANGE_NOT_SATISFIABLE_MSG           "Range Not Satisfiable"
#define NOA_STATUS_EXPECTATION_FAILED_MSG              "Expectation Failed"
#define NOA_STATUS_IM_A_TEAPOT_MSG                     "I'm a teapot"
#define NOA_STATUS_MISDIRECTED_REQUEST_MSG             "Misdirected Request"
#define NOA_STATUS_UNPROCESSABLE_CONTENT_MSG           "Unprocessable Content"
#define NOA_STATUS_LOCKED_MSG                          "Locked"
#define NOA_STATUS_FAILED_DEPENDENCY_MSG               "Failed Dependency"
#define NOA_STATUS_TOO_EARLY_MSG                       "Too Early"
#define NOA_STATUS_UPGRADE_REQUIRED_MSG                "Upgrade Required"
#define NOA_STATUS_PRECONDITION_REQUIRED_MSG           "Precondition Required"
#define NOA_STATUS_TOO_MANY_REQUESTS_MSG               "Too Many Requests"
#define NOA_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE_MSG "Request Header Fields Too Large"
#define NOA_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS_MSG   "Unavailable For Legal Reasons"

typedef struct {
    char *name;
    char *value;
} NoaHeader;

typedef struct {
    uint32_t   valid;
    NoaMethod  method;
    char      *path;
    NoaHeader *headers;
    char      *data;
    size_t     data_size;
    uint32_t   header_count;
    uint8_t    version_major;
    uint8_t    version_minor;
    int32_t    websocket_upgrade_requested;
    char      *websocket_key;
    int32_t    websocket_version;
} NoaRequest;

typedef struct {
    uint32_t    status_code;
    const char *status_message;
    const char *data;
    size_t      data_size;
    NoaHeader  *headers;
    uint32_t    header_count;
} NoaResponse;

typedef struct {
    PlatformSocket fd;
    uint32_t       id;
    uint64_t       uid;
    int32_t        is_keep_alive;
    int64_t        last_active_timestamp;
    uint32_t       remaining_requests;
    int32_t        has_data;
    int32_t        is_websocket;
    int32_t        is_waiting_for_pong;
} NoaConnection;

typedef enum {
    NOA_WS_OPCODE_CONTINUATION = 0x0,
    NOA_WS_OPCODE_TEXT         = 0x1,
    NOA_WS_OPCODE_BINARY       = 0x2,
    NOA_WS_OPCODE_CLOSE        = 0x8,
    NOA_WS_OPCODE_PING         = 0x9,
    NOA_WS_OPCODE_PONG         = 0xA,
} NoaWebsocketOpcode;

typedef struct {
    int32_t            valid;
    uint8_t            fin;
    uint8_t            rsv1;
    uint8_t            rsv2;
    uint8_t            rsv3;
    NoaWebsocketOpcode opcode;
    uint64_t           payload_length;
    uint8_t           *payload;
} NoaWebsocketMessage;

void noa_init(const char *address, uint16_t port);
int32_t noa_must_process_connections(void);
int32_t noa_receive_request(NoaConnection *connection, NoaRequest *request);
NoaConnection *noa_next_client(void);
NoaConnection *noa_get_connection(uint64_t uid);
void noa_respond(NoaConnection *connection, NoaResponse *response);
int32_t noa_websocket_send(NoaConnection *connection, NoaWebsocketMessage *message);
void noa_upgrade_connection(NoaConnection *connection, NoaRequest *request);
int32_t noa_receive_websocket_message(NoaConnection *connection, NoaWebsocketMessage *message);
void noa_return_websocket_message(NoaWebsocketMessage *message);
void noa_websocket_close(NoaConnection *connection);

#ifdef __cplusplus
}
#endif

#endif // _NOA_H_
