#!/bin/sh

set -e

emcc -o wasm/cli.js -O3 -flto --no-entry \
     -Wall -Wextra \
     -s STACK_OVERFLOW_CHECK=1 \
     -s STACK_SIZE=8388608 \
     -s INITIAL_MEMORY=134217728 \
     -s MAXIMUM_MEMORY=4294967296 \
     -s ALLOW_MEMORY_GROWTH=1 \
     -s MODULARIZE=1 \
     -s ENVIRONMENT=worker \
     -s EXPORT_ES6=1 \
     -s EXPORTED_FUNCTIONS='[_malloc]' \
     -s EXPORTED_RUNTIME_METHODS=HEAPU8 \
     -s SUPPORT_LONGJMP=0 \
     -s FILESYSTEM=0 \
     -s ASYNCIFY \
     -fno-exceptions \
     -fno-rtti \
     -DEMSCRIPTEN_HAS_UNBOUND_TYPE_NAMES=0 \
     client/emscripten_main.cc client/client.c \
     -lembind
      
cp wasm/* webui/src/wasm/
ls -lah webui/src/wasm/cli*
