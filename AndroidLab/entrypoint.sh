#!/bin/sh
set -eu
umask 077
mkdir -p /data
if [ ! -f /data/lab.keystore ]; then
  keytool -genkeypair -alias zeus-lab -keyalg RSA -keysize 2048 -validity 3650 \
    -keystore /data/lab.keystore -storepass android -keypass android \
    -dname 'CN=ZEUS Android Lab' >/dev/null 2>&1
fi
# The certificate/password are a laboratory signing identity, not an app-store
# identity. Separate unprivileged build tools can access only their keystore copy.
install -o 10002 -g 10002 -m 0400 /data/lab.keystore /tmp/zeus-build.keystore
export ZEUS_ANDROID_KEYSTORE=/tmp/zeus-build.keystore
exec python -m zeus_android
