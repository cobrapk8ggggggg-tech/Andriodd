"""Bounded agent-in-the-loop test: immutable observations, reviewed allowlisted actions."""
import asyncio
import base64
import json
import os
from pathlib import Path
import shutil
import signal
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

from zeus_android.device import Device
from tls_origin import start_origin,install_interception_ca
from download import prepare

PROOF=Path(os.environ['CHATGPT_PROOF_DIR']).resolve()
REPO=os.environ['GITHUB_REPOSITORY'];BRANCH=os.environ['GITHUB_REF_NAME']
SESSION=json.loads(Path('experiments/chatgpt-trial/launch.json').read_text())['session']
PACKAGE='com.openai.chatgpt';DEVICE=Device('emulator-5554');children=[]
RESULT={'session':SESSION,'package':PACKAGE,'agent_actions':[],'credentials_entered':False,'message_delivery':'not_verified'}

def write(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2))
def ready(sequence,directory):
    temporary=PROOF/f'ready-{sequence}.tmp';write(temporary,{'sequence':sequence,'directory':directory.name});temporary.rename(PROOF/f'ready-{sequence}.json')
def clean_env(extra=None):
    env={k:os.environ[k] for k in ['PATH','HOME','LANG','JAVA_HOME','ANDROID_HOME','ANDROID_SDK_ROOT','ANDROID_USER_HOME'] if k in os.environ}
    return {**env,**(extra or {})}
def network(since=0):
    values=[];path=PROOF/'capture.jsonl'
    if path.exists():
        for line in path.read_text().splitlines():
            try:
                item=json.loads(line)
                if item.get('timestamp',0)>=since:values.append(item)
            except ValueError:pass
    return values
async def snapshot(sequence,action,since):
    directory=PROOF/f'round-{sequence}';directory.mkdir(exist_ok=True)
    try:directory.joinpath('screen.jpg').write_bytes(await DEVICE.screenshot())
    except Exception as error:write(directory/'screenshot-error.json',{'error':str(error)})
    try:tree=await DEVICE.action('tree',{})
    except Exception as error:tree={'nodes':[],'error':str(error)}
    write(directory/'observation.json',{'sequence':sequence,'observed_at':time.time(),'action':action,'tree':tree,'network':network(since),'result_so_far':RESULT})
    ready(sequence,directory)

def control():
    path='experiments/chatgpt-trial/control.json'
    url='https://api.github.com/repos/'+REPO+'/contents/'+path+'?ref='+urllib.parse.quote(BRANCH,safe='')
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+os.environ['GITHUB_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Cache-Control':'no-cache'})
    with urllib.request.urlopen(request,timeout=10) as response:value=json.load(response)
    data=json.loads(base64.b64decode(value['content']))
    if data.get('session')!=SESSION:raise ValueError('Control belongs to another trial')
    return data

async def execute(command):
    operation=command['operation']
    if operation=='type':
        import re
        text=command.get('text','')
        if isinstance(text,str) and re.fullmatch(r'[A-Za-z0-9 ]{1,200}',text):
            await DEVICE.command('shell','input','text',text.replace(' ','%s'));return {'typed_with':'system_input_ascii'}
        return await DEVICE.action(operation,command)
    if operation in {'tap','swipe','key'}:return await DEVICE.action(operation,command)
    if operation=='launch':return await DEVICE.action('launch',{'package':PACKAGE})
    if operation=='observe':return {'observed':True}
    if operation=='network':
        mode=command.get('mode')
        if mode not in {'on','off'}:raise ValueError('Invalid network mode')
        await DEVICE.command('shell','settings','put','global','http_proxy','10.0.2.2:8089' if mode=='on' else ':0')
        RESULT['proxy_enabled']=mode=='on';return {'proxy_enabled':RESULT['proxy_enabled']}
    if operation=='stop':return {'stop':True}
    raise ValueError('Action is outside the test allowlist')

async def main():
    PROOF.mkdir(parents=True,exist_ok=True);initial=PROOF/'setup';initial.mkdir(exist_ok=True);write(initial/'scope.json',RESULT);ready(900,initial)
    origin=None;files=[];deadline=time.monotonic()+1000;code=0
    try:
        with tempfile.TemporaryDirectory(prefix='zeus-chatgpt-') as directory:
            root=Path(directory)
            paths,metadata=await asyncio.to_thread(prepare,root/'app');RESULT['application']=metadata;write(PROOF/'application.json',metadata)
            await asyncio.to_thread(subprocess.run,['avdmanager','create','avd','-n','zeus-chatgpt','-k','system-images;android-32;google_apis;x86_64','--force'],input=b'no\n',env=clean_env(),capture_output=True,check=True,timeout=90)
            log=(PROOF/'emulator.log').open('wb');files.append(log)
            executable=str(Path((os.environ.get('ANDROID_HOME') or os.environ['ANDROID_SDK_ROOT']))/'emulator/emulator')
            emulator=subprocess.Popen([executable,'-avd','zeus-chatgpt','-no-window','-noaudio','-no-boot-anim','-no-snapshot','-gpu','swiftshader_indirect','-memory','2048','-cores','2','-writable-system','-port','5554'],env=clean_env(),stdout=log,stderr=log,start_new_session=True);children.append(emulator)
            for attempt in range(180):
                if emulator.poll() is not None:raise RuntimeError('Emulator exited: '+str(emulator.returncode))
                try:
                    if (await DEVICE.command('shell','getprop','sys.boot_completed',timeout=3)).strip()==b'1':break
                except (ValueError,asyncio.TimeoutError):pass
                if attempt==179:raise RuntimeError('Android boot timeout')
                await asyncio.sleep(1)
            RESULT['guest_abis']=(await DEVICE.command('shell','getprop','ro.product.cpu.abilist')).decode().strip()
            RESULT['guest_api']=(await DEVICE.command('shell','getprop','ro.build.version.sdk')).decode().strip()
            origin,origin_ca=start_origin(root)
            combined=root/'upstream-ca.pem';combined.write_bytes(Path(ssl.get_default_verify_paths().cafile).read_bytes()+origin_ca.read_bytes())
            capture_log=(PROOF/'capture.log').open('wb');files.append(capture_log)
            capture=subprocess.Popen([os.environ['LAB_CAPTURE_EXE'],'--listen-host','127.0.0.1','--listen-port','8089','--set','connection_strategy=lazy','--set','confdir='+str(root/'ca'),'--set','ssl_verify_upstream_trusted_ca='+str(combined),'-s','AndroidLab/tests/route_probe.py','-s','experiments/chatgpt-trial/capture.py'],env=clean_env({'PYTHONPATH':str(Path('AndroidLab').resolve()),'CHATGPT_CAPTURE_FILE':str(PROOF/'capture.jsonl')}),stdout=capture_log,stderr=capture_log,start_new_session=True);children.append(capture)
            for _ in range(100):
                if (root/'ca/mitmproxy-ca-cert.pem').exists():break
                await asyncio.sleep(.1)
            try:
                await install_interception_ca(DEVICE,root/'ca/mitmproxy-ca-cert.pem',PROOF/'system-ca-setup.log');RESULT['system_ca_installed']=True
            except Exception as error:RESULT.update(system_ca_installed=False,ca_error=type(error).__name__+': '+str(error))
            # adb reboot can close its transport before the command returns.
            # Require stable boot/package-manager reads before any UI operation.
            stable=0
            for attempt in range(150):
                try:
                    boot=(await DEVICE.command('shell','getprop','sys.boot_completed',timeout=3)).strip()==b'1'
                    package=await DEVICE.command('shell','pm','path','android',timeout=3)
                    stable=stable+1 if boot and b'package:' in package else 0
                    if stable>=3:break
                except (ValueError,asyncio.TimeoutError):stable=0
                if attempt==149:raise RuntimeError('Android did not return after certificate provisioning')
                await asyncio.sleep(1)
            await DEVICE.command('shell','wm','dismiss-keyguard')
            await DEVICE.command('shell','input','keyevent','82')
            digest=subprocess.check_output(['openssl','x509','-in',str(root/'ca/mitmproxy-ca-cert.pem'),'-subject_hash_old','-noout'],text=True).strip()
            try:
                await DEVICE.command('shell','ls','/system/etc/security/cacerts/'+digest+'.0');RESULT['system_ca_file_present']=True
            except ValueError:RESULT['system_ca_file_present']=False
            # Verify the capture infrastructure independently; never attribute this fixture to ChatGPT.
            if RESULT['system_ca_file_present']:
                try:
                    await DEVICE.command('install','-r',os.environ['LAB_PROBE_APK'],timeout=90)
                    await DEVICE.command('shell','settings','put','global','http_proxy','10.0.2.2:8089')
                    await DEVICE.action('launch',{'package':'com.zeus.lab.probe'});await asyncio.sleep(2)
                    node=None
                    for _ in range(5):
                        tree=await DEVICE.action('tree',{});node=next((n for n in tree['nodes'] if n.get('content-desc')=='probeSend'),None)
                        if node:break
                        await asyncio.sleep(1)
                    if not node:raise ValueError('TLS control fixture did not show its send button')
                    width,height=await DEVICE.size()
                    import re
                    left,top,right,bottom=map(int,re.findall(r'\d+',node['bounds']))
                    await DEVICE.action('tap',{'x':(left+right)/2/width,'y':(top+bottom)/2/height})
                    for _ in range(40):
                        events=network();found=next((e for e in events if e.get('url','').endswith('/probe') and e.get('phase')=='complete' and e.get('status')==200),None)
                        if found:break
                        await asyncio.sleep(.2)
                    RESULT['tls_control_passed']=bool(found);write(PROOF/'tls-control.json',{'passed':bool(found),'fixture':'com.zeus.lab.probe','event':found})
                except Exception as error:RESULT.update(tls_control_passed=False,tls_control_error=str(error))
                await DEVICE.command('shell','am','force-stop','com.zeus.lab.probe')
            await DEVICE.command('shell','settings','put','global','http_proxy',':0')
            await DEVICE.command('install-multiple','-r',*paths,timeout=150)
            RESULT['installed']=True
            proxy=bool(RESULT.get('tls_control_passed'));RESULT['proxy_enabled']=proxy
            await DEVICE.command('shell','settings','put','global','http_proxy','10.0.2.2:8089' if proxy else ':0')
            (PROOF/'capture.jsonl').write_text('')
            (PROOF/'capture.epoch').write_text(SESSION)
            RESULT['capture_scope']=['openai.com','chatgpt.com','sentry.io']
            since=time.time()
            await DEVICE.action('launch',{'package':PACKAGE});RESULT['launched']=True;await asyncio.sleep(8)
            await snapshot(0,{'operation':'launch','proxy_enabled':proxy},since)
            deadline=min(deadline,time.monotonic()+600);next_sequence=1
            while time.monotonic()<deadline and next_sequence<=8:
                await asyncio.sleep(3)
                try:command=await asyncio.to_thread(control)
                except Exception as error:
                    print('Control unavailable: '+type(error).__name__,flush=True);continue
                if command.get('sequence')!=next_sequence:continue
                since=time.time();record={k:v for k,v in command.items() if k in {'sequence','operation','x','y','x2','y2','text','key','mode','label'}}
                try:record['execution']=await execute(command)
                except Exception as error:record['error']=str(error)
                RESULT['agent_actions'].append(record);await asyncio.sleep(min(15,max(1,int(command.get('settle_seconds',4)))))
                await snapshot(next_sequence,record,since);next_sequence+=1
                if command['operation']=='stop':RESULT['ended']='operator_stop';break
            else:RESULT['ended']='deadline_or_action_limit'
    except Exception as error:
        RESULT['setup_error']=str(error);code=1
        try:await snapshot(0,{'operation':'setup_failed'},0)
        except Exception:pass
    finally:
        for child in children:
            if child.poll() is None:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:pass
        if origin:await asyncio.to_thread(origin.shutdown);origin.server_close()
        for file in files:file.close()
        final=PROOF/'final';final.mkdir(exist_ok=True)
        write(final/'result.json',RESULT)
        for path in PROOF.glob('round-*'):
            if path.is_dir():shutil.copytree(path,final/path.name,dirs_exist_ok=True)
        for name in ['capture.jsonl','tls-control.json','application.json']:
            if (PROOF/name).exists():shutil.copy2(PROOF/name,final/name)
        ready(99,final);print('CHATGPT_TRIAL_FINISHED '+json.dumps(RESULT,ensure_ascii=False),flush=True)
    return code

if __name__=='__main__':raise SystemExit(asyncio.run(main()))
