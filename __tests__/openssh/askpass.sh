#!/bin/sh
case "$1" in
    *OTP*) printf '%s\n' '654321' ;;
    *[Nn]ew*|*[Rr]etype*|*[Aa]gain*) printf '%s\n' 'new-password' ;;
    *) printf '%s\n' 'correct-horse-battery-staple' ;;
esac
