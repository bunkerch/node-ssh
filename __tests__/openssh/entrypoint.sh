#!/bin/sh
set -eu

rm -f /tmp/echo.sock
socat UNIX-LISTEN:/tmp/echo.sock,fork,mode=0777 EXEC:/bin/cat &
exec /usr/sbin/sshd -D -e
