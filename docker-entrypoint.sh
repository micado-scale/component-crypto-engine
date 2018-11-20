#!/bin/bash

CAFILE="/opt/cryptoengine/app/CA_key.pem"

if [ ! -f "$CAFILE" ]; then
    /usr/bin/openssl genrsa -out "$CAFILE" 4096
fi;

exec "$@"
