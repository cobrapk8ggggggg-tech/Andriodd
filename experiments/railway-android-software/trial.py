"""Bounded software-only Android trial. No public ADB, personal APKs or persistence."""
import hashlib
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time

DURATION=max(1,min(900,int(os.environ.get('ZEUS_TRIAL_SECONDS','900'))))
SDK='/opt/android-sdk';ADB=SDK+'/platform-tools/adb';EMU=SDK+'/emulator/emulator'
started=time.monotonic();children=[];result={'booted':False,'acceleration':'off','duration_limit_seconds':DURATION}
finished=threading.Event()

def resources():
    values={}
    for name in ['memory.events','memory.current','memory.peak','memory.max','pids.events']:
        try:values[name]=Path('/sys/fs/cgroup',name).read_text()[:1500].strip()
        except OSError:pass
    return values

def event(name,**fields):print('ZEUS_ANDROID_SOFTWARE_TRIAL '+json.dumps({'event':name,'elapsed_seconds':round(time.monotonic()-started,2),**fields}),flush=True)

def stop_children():
    for child in children:
        if child.poll() is None:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
    for child in children:
        try:child.wait(timeout=2)
        except subprocess.TimeoutExpired:pass

def watchdog():
    if not finished.wait(DURATION+8):
        stop_children();event('hard_deadline',**result);os._exit(0)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path=='/health' else 404);self.end_headers()
        self.wfile.write(b'{"ok":true,"mode":"bounded-android-trial"}')
    def log_message(self,*a):pass

def main():
    server=HTTPServer(('0.0.0.0',int(os.environ.get('PORT','8080'))),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    threading.Thread(target=watchdog,daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='zeus-android-trial-') as folder:
            root=Path(folder);avd=root/'avd';avd.mkdir();device=avd/'zeus.avd';device.mkdir()
            (avd/'zeus.ini').write_text('avd.ini.encoding=UTF-8\npath='+str(device)+'\ntarget=android-29\n')
            (device/'config.ini').write_text('\n'.join(['AvdId=zeus','avd.ini.encoding=UTF-8','abi.type=x86_64','hw.cpu.arch=x86_64','hw.cpu.ncore=1','hw.ramSize=512','hw.lcd.width=360','hw.lcd.height=640','hw.lcd.density=160','hw.gpu.enabled=no','hw.gpu.mode=off','hw.keyboard=yes','hw.sdCard=no','disk.dataPartition.size=800M','image.sysdir.1='+SDK+'/system-images/android-29/default/x86_64/','tag.id=default','tag.display=Default','PlayStore.enabled=false'])+'\n')
            env={'PATH':os.environ['PATH'],'HOME':folder,'LANG':'C.UTF-8','ANDROID_HOME':SDK,'ANDROID_SDK_ROOT':SDK,'ANDROID_AVD_HOME':str(avd),'ANDROID_EMULATOR_HOME':str(root/'emulator')}
            def adb(*args,timeout=5,binary=False):
                value=subprocess.run([ADB,'-s','emulator-5554',*args],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
                if value.returncode:raise RuntimeError(value.stderr.decode(errors='replace')[:400])
                return value.stdout if binary else value.stdout.decode(errors='replace').strip()
            # Keep the ADB daemon a tracked foreground child for guaranteed cleanup.
            daemon=subprocess.Popen([ADB,'-L','tcp:localhost:5037','nodaemon','server'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True);children.append(daemon)
            log_path=root/'emulator.log'
            with log_path.open('wb') as log:
                args=[EMU,'-avd','zeus','-accel','off','-no-window','-no-audio','-no-boot-anim','-no-snapshot','-no-metrics','-gpu','off','-feature','-Vulkan','-memory','512','-cores','1','-port','5554','-wipe-data']
                child=subprocess.Popen(args,env=env,stdout=log,stderr=log,start_new_session=True);children.append(child)
                event('started',command=args,kvm_present=Path('/dev/kvm').exists(),android_api=29,resources=resources())
                last=-30
                while time.monotonic()-started<DURATION:
                    if child.poll() is not None:
                        result.update(reason='emulator_exit',exit_code=child.returncode);break
                    try:
                        if adb('shell','getprop','sys.boot_completed')=='1':
                            result.update(booted=True,boot_seconds=round(time.monotonic()-started,2),android_release=adb('shell','getprop','ro.build.version.release'),sdk=adb('shell','getprop','ro.build.version.sdk'))
                            event('boot_completed',**result)
                            ui=adb('shell','am','start','-a','android.settings.SETTINGS',timeout=15)
                            time.sleep(2)
                            picture=adb('exec-out','screencap','-p',timeout=20,binary=True)
                            if not picture.startswith(b'\x89PNG\r\n\x1a\n'):raise RuntimeError('Invalid Android screenshot')
                            result.update(settings_launch=ui[:500],screenshot_bytes=len(picture),screenshot_sha256=hashlib.sha256(picture).hexdigest())
                            result['reason']='boot_and_ui_verified';break
                    except (RuntimeError,subprocess.TimeoutExpired) as error:
                        if result['booted']:result.update(reason='post_boot_failure',error=str(error)[:400]);break
                    if time.monotonic()-started-last>=30:
                        last=time.monotonic()-started
                        event('waiting',emulator_alive=child.poll() is None)
                    time.sleep(1)
                else:result['reason']='boot_deadline'
            stop_children()
            with log_path.open('rb') as saved:
                saved.seek(max(0,log_path.stat().st_size-12000));tail=saved.read(12000).decode(errors='replace')
            with log_path.open('rb') as saved:
                first=saved.read(100000).decode(errors='replace')
            for line in [v for v in first.splitlines() if any(word in v.lower() for word in ['memory','ram size','error','fatal','accel'])][:20]:event('diagnostic',line=line[:700])
            for line in tail.splitlines()[-45:]:event('emulator_log',line=line[:700])
    except Exception as error:result.update(reason='setup_failure',error=str(error)[:700])
    finally:
        stop_children();event('finished',**result,resources=resources());finished.set();server.shutdown();server.server_close()

if __name__=='__main__':main()
