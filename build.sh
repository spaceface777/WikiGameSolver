#!/bin/bash

/opt/cosmocc-linux/bin/x86_64-unknown-cosmo-cc client/client.c -DENABLE_SERVER -o cli.com.dbg -O3 && x86_64-linux-cosmo-objcopy -SO binary cli.com.dbg cli && rm cli.com.dbg

