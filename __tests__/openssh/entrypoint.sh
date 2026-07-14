#!/bin/sh
set -eu

rm -f /tmp/echo.sock
socat UNIX-LISTEN:/tmp/echo.sock,fork,mode=0777 EXEC:/bin/cat &
socat TCP-LISTEN:18080,reuseaddr,fork EXEC:/usr/local/bin/modernssh-http-response &
exec /usr/sbin/sshd -D -e
