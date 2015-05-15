#!/bin/bash

host="${1:-localhost:3799}"
mac="${2:-78:2b:cb:bd:33:18}"

cat <<EOF | radclient -i 10 -x $host coa testing123
#Message-Authenticator = 0x00
User-Name = '$mac+coa'
Session-Timeout := 12345
EOF

