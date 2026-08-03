#!/bin/sh
while IFS= read -r line; do
    [ "$line" = "$(printf '\r')" ] && break
done
printf 'HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nopenssh-http\n'
