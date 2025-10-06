#!/bin/bash

# check if --debug flag is passed
if [ "$1" == "--debug" ]; then
    CFLAGS="-g -Og -DDEBUG -mdbg"
else
    CFLAGS="-O3"
fi

/opt/cosmocc/bin/cosmocc client/client.c -DENABLE_SERVER -Wall -Wextra -o cli.com $CFLAGS
