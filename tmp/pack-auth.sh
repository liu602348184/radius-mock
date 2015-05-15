#!/bin/bash

host="${1:-localhost:1812}"
mac="${2:-78:2b:cb:bd:33:18}"

echo "Enviando para $host"

cat <<EOF | radclient -x $host auth testing123
#Message-Authenticator = 0x00
User-Name = 'pacote-auth-$mac'
Session-Timeout := 54321
EOF

