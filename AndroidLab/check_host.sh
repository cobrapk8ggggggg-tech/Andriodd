#!/bin/sh
set -eu
printf 'Architecture: '; uname -m
docker info --format 'Docker: {{.OSType}} / {{.Architecture}}'
if [ ! -d /sys/module/binder_linux ] && [ ! -e /dev/binder ] && [ ! -d /dev/binderfs ]; then
  echo 'BLOCKED: the host needs Android binder support; no kernel changes were made.' >&2
  exit 42
fi
awk '/MemTotal/ {printf "Host memory: %.1f GiB\n",$2/1048576}' /proc/meminfo
df -h .
echo 'Host probe passed. Device boot, graphics, TLS capture and mobile WebRTC still need actual testing.'
