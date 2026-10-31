"""A short-lived network observer with no GitHub/model credential inheritance."""
import asyncio
import os
from pathlib import Path
import shutil
import signal
import sys
import ssl


class CaptureRuntime:
    def __init__(self, private, data, device, token, fixture=False):
        self.private, self.data, self.device, self.token = private, data, device, token
        self.fixture, self.process, self.log, self.origin = fixture, None, None, None

    async def start(self):
        executable = os.environ.get('LAB_CAPTURE_EXE')
        if not executable or not Path(executable).is_file():
            raise ValueError('mitmproxy is not installed in this Actions runtime')
        uid = 10003
        conf = self.private / 'capture-ca'
        conf.mkdir(mode=0o700)
        os.chown(conf, uid, uid)
        addon = self.private / 'capture-addon.py'
        shutil.copyfile('AndroidLab/zeus_android/capture.py', addon)
        addon.chmod(0o444)
        command = [executable, '--quiet', '--listen-host', '127.0.0.1', '--listen-port', '8089',
                   '--set', 'connection_strategy=lazy', '--set', 'confdir=' + str(conf), '-s', str(addon)]
        if self.fixture:
            # This route exists only for the repository's controlled test app.
            sys.path.insert(0, str(Path('AndroidLab/tests').resolve()))
            from tls_origin import start_origin
            self.origin, public_ca = start_origin(self.private, hold=True)
            public_ca.chmod(0o444)
            # Adding the fixture root must not remove the system's real roots
            # or manufacture TLS failures for unrelated Android services.
            bundle=self.private/'fixture-upstream-roots.pem'
            roots=ssl.get_default_verify_paths().cafile
            bundle.write_bytes((Path(roots).read_bytes() if roots else b'')+b'\n'+public_ca.read_bytes());bundle.chmod(0o444)
            route = self.private / 'controlled-origin-route.py'
            shutil.copyfile('AndroidLab/tests/route_probe.py', route)
            route.chmod(0o444)
            command += ['--set', 'ssl_verify_upstream_trusted_ca=' + str(bundle), '-s', str(route)]
        self.log = (self.data / 'capture-runtime.log').open('wb')
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(conf), 'LANG': 'C.UTF-8',
               'ZEUS_ANDROID_CAPTURE_ENDPOINT': 'http://127.0.0.1:8088/internal/capture',
               'ZEUS_ANDROID_CAPTURE_TOKEN': self.token}
        self.process = await asyncio.create_subprocess_exec(
            'prlimit', '--fsize=8388608', '--nproc=128', '--nofile=256', '--', *command,
            user=uid, group=uid, extra_groups=[], cwd='/tmp', env=env,
            stdout=self.log, stderr=self.log, start_new_session=True)
        certificate = conf / 'mitmproxy-ca-cert.pem'
        for _ in range(200):
            if self.process.returncode is not None:
                raise ValueError('Network observer exited during startup; inspect its private runtime log')
            if certificate.is_file():
                os.environ.update(ZEUS_ANDROID_PROXY='10.0.2.2:8089', ZEUS_ANDROID_CAPTURE_READY='1')
                return certificate
            await asyncio.sleep(.1)
        raise ValueError('Network observer did not initialize its certificate')

    async def close(self):
        os.environ['ZEUS_ANDROID_CAPTURE_READY'] = '0'
        if self.origin:
            self.origin.release.set()
            await asyncio.to_thread(self.origin.shutdown)
            self.origin.server_close()
        if self.process and self.process.returncode is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(self.process.wait(), 3)
            except asyncio.TimeoutError:
                os.killpg(self.process.pid, signal.SIGKILL)
                await self.process.wait()
        if self.log:
            self.log.close()
