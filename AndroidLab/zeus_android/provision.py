"""Temporary CA-store overlay inside a disposable userdebug Android guest.

The in-memory store preserves the device's existing roots. It avoids modifying
verified partitions or rebooting the emulator. Android 14+ APEX namespaces are
handled separately; the currently verified lab profile is API 32.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile


async def install_interception_ca(device, certificate, log_path=None):
    if os.environ.get('ZEUS_ANDROID_EXTERNAL_AVD') != '1':
        raise ValueError('CA provisioning requires the disposable lab AVD')
    api = int((await device.command('shell', 'getprop', 'ro.build.version.sdk')).strip())
    if not 29 <= api <= 35 or (await device.command('shell', 'getprop', 'ro.debuggable')).strip() != b'1':
        raise ValueError('This image does not support the lab system-CA profile')
    digest = subprocess.check_output(['openssl', 'x509', '-in', str(certificate), '-subject_hash_old', '-noout'], text=True).strip()
    if not re.fullmatch('[0-9a-f]{8}', digest):
        raise ValueError('Invalid CA subject hash')
    output = []
    async def step(*args, **kwargs):
        value = await device.command(*args, **kwargs)
        output.append(' '.join(args) + '\n' + value.decode(errors='replace'))
        return value
    script = '''set -eu
SYSTEM=/system/etc/security/cacerts
COPY=/data/local/tmp/zeus-ca-original
mkdir -p "$COPY"
chmod 700 "$COPY"
if [ -d /apex/com.android.conscrypt/cacerts ]; then
    cp /apex/com.android.conscrypt/cacerts/* "$COPY/"
else
    cp "$SYSTEM"/* "$COPY/"
fi
mount -t tmpfs -o mode=0755,size=16m tmpfs "$SYSTEM"
cp "$COPY"/* "$SYSTEM/"
cp /data/local/tmp/ZEUS_CERT.0 "$SYSTEM/ZEUS_CERT.0"
chown 0:0 "$SYSTEM"/*
chmod 644 "$SYSTEM"/*
chcon u:object_r:system_file:s0 "$SYSTEM"
chcon u:object_r:system_file:s0 "$SYSTEM"/*
if [ -d /apex/com.android.conscrypt/cacerts ]; then
    mount --bind "$SYSTEM" /apex/com.android.conscrypt/cacerts
    for name in zygote zygote64 webview_zygote; do
        for pid in $(pidof "$name" || true); do
            nsenter --mount=/proc/$pid/ns/mnt -- mount --bind "$SYSTEM" /apex/com.android.conscrypt/cacerts
        done
    done
fi
rm -rf "$COPY"
echo ZEUS_CA_READY
'''.replace('ZEUS_CERT', digest)
    try:
        await step('root')
        await step('wait-for-device', timeout=30)
        if (await device.command('shell', 'id', '-u')).strip() != b'0':
            raise ValueError('The disposable Android image did not grant adb root')
        await step('push', str(certificate), '/data/local/tmp/' + digest + '.0')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'zeus-ca.sh';path.write_text(script)
            await step('push', str(path), '/data/local/tmp/zeus-ca.sh')
        result = await step('shell', 'sh', '/data/local/tmp/zeus-ca.sh', timeout=30)
        if b'ZEUS_CA_READY' not in result:
            raise ValueError('The temporary Android CA store was not initialized')
        installed = await device.command('exec-out', 'cat', '/system/etc/security/cacerts/' + digest + '.0')
        if installed != Path(certificate).read_bytes():
            raise ValueError('The installed CA does not match this lab session')
        return {'store': 'disposable_avd_tmpfs', 'api': api, 'rebooted': False,
                'certificate_sha256': hashlib.sha256(installed).hexdigest()}
    finally:
        if log_path:
            Path(log_path).write_text('\n'.join(output))
