"""Single-command deployment fallback: inline PAYLOAD contains the two reviewed scripts."""
import base64
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
import zlib

started=time.monotonic();deadline=started+900;children=[];done=threading.Event()
def event(name,**fields):print('ZEUS_ANDROID_SOFTWARE_BOOTSTRAP '+json.dumps({'event':name,'elapsed_seconds':round(time.monotonic()-started,2),**fields}),flush=True)
def cleanup():
    for child in children:
        if child.poll() is None:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():continue
        try:
            if str((process/'exe').resolve()).startswith('/opt/android-sdk/emulator/'):
                os.kill(int(process.name),signal.SIGKILL)
        except (OSError,ProcessLookupError):pass

def watchdog():
    if not done.wait(900):cleanup();event('hard_deadline');os._exit(0)
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):self.send_response(200 if self.path=='/health' else 404);self.end_headers();self.wfile.write(b'{"ok":true,"phase":"preparing-bounded-trial"}')
    def log_message(self,*args):pass

def main():
    threading.Thread(target=watchdog,daemon=True).start()
    server=HTTPServer(('0.0.0.0',int(os.environ.get('PORT','8080'))),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        env={'PATH':os.environ['PATH'],'HOME':'/tmp','LANG':'C.UTF-8','DEBIAN_FRONTEND':'noninteractive'}
        def command(args,timeout):
            child=subprocess.Popen(args,env=env,start_new_session=True);children.append(child)
            try:code=child.wait(timeout=min(timeout,max(1,deadline-time.monotonic()-10)))
            except subprocess.TimeoutExpired:raise RuntimeError('Preparation time limit exceeded')
            if code:raise RuntimeError('Preparation command failed: '+args[0]+' exit='+str(code))
        event('started',total_limit_seconds=900)
        command(['apt-get','update','-qq'],120)
        packages=['ca-certificates','libstdc++6','libpulse0','libnss3','libdbus-1-3','libx11-6','libxcb1','libxcb-cursor0','libxcb-xinerama0','libxcb-keysyms1','libxcomposite1','libxcursor1','libxdamage1','libxi6','libxrandr2','libxtst6','libxkbcommon0','libgl1','libegl1','libglu1-mesa','libvulkan1','libasound2','libfontconfig1','libfreetype6','libxkbfile1','libtcmalloc-minimal4','libglib2.0-0']
        command(['apt-get','install','-y','-qq','--no-install-recommends',*packages],180)
        with tempfile.TemporaryDirectory(prefix='zeus-software-code-') as directory:
            root=Path(directory)
            payload=json.loads(zlib.decompress(base64.b64decode(PAYLOAD)))
            for name in ['download_sdk.py','trial.py']:(root/name).write_text(payload[name])
            command(['python3','-u',str(root/'download_sdk.py')],480)
            env.update(ANDROID_HOME='/opt/android-sdk',ANDROID_SDK_ROOT='/opt/android-sdk',PATH='/opt/android-sdk/emulator:/opt/android-sdk/platform-tools:'+env['PATH'],PORT=os.environ.get('PORT','8080'),ZEUS_TRIAL_SECONDS=str(max(1,int(deadline-time.monotonic()-12))))
            event('prepared',remaining_seconds=int(deadline-time.monotonic()))
            server.shutdown();server.server_close();server=None
            command(['python3','-u',str(root/'trial.py')],max(1,deadline-time.monotonic()-5))
    except Exception as error:event('failed',error=str(error)[:600])
    finally:
        cleanup()
        if server:server.shutdown();server.server_close()
        event('finished');done.set()

if __name__=='__main__':main()
