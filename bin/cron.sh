#!/bin/sh -e

delay="$1"
lock="$2"
shift 2

flock --exclusive --nonblock "$lock" randsleep 0 "$delay" "$lock"

# Race between two `flock's is negligible. All in all the first one is needed
# just to avoid one(!) dangling `sleep`.

# `--close` is important for FreeBSD as `service` does not talk to `init`,
# but launches services in-place, so file descriptor leaking from cron-based
# watchdog to daemon prevents the watchdog from functioning correctly.

exec flock --exclusive --nonblock --close "$lock" "$@"
