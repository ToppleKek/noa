#!/bin/bash

OS="$(uname)"

if [ $OS = "Linux" ]; then
    LIBS=-lm
fi

set -e

mkdir -p build

# ECHO SERVER
clang examples/echo.c noa.c ${LIBS} -g -o build/echo.exe
# BASIC SERVER EXAMPLE
clang examples/basic.c noa.c ${LIBS} -g -o build/basic.exe
# WEBSOCKET ECHO SERVER EXAMPLE
clang examples/websocket_echo.c noa.c ${LIBS} -g -o build/websocket_echo.exe
# WEBSOCKET CHAT SERVER EXAMPLE
clang examples/websocket_chat.c noa.c ${LIBS} -g -o build/websocket_chat.exe
