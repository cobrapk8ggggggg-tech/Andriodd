"""Bounded real-AVD acceptance. Only client-key-encrypted artifacts are published."""
import asyncio,hashlib,json,os,re,secrets,signal,sqlite3,subprocess,tarfile,tempfile,time,urllib.request,uuid
from pathlib import Path
import httpx,uvicorn
from urllib.parse import quote
from zeus_android.app import create_app
from zeus_android.device import Device
from capture_runtime import CaptureRuntime
from verify_capture import verify_capture
from signing import prepare_signing_key
from verify_rebuild import verify_rebuild
from zeus_android.provision import install_interception_ca
from zeus_android.mailbox import EmergencyMailbox
from zeus_android.transfers import download_asset
from zeus_android.projects import MAX_APK
from zeus_android.archives import snapshot,restore_projects,MAX_ARCHIVE
from zeus_android.tokens import encode
from zeus_android.sealed import seal,seal_file
from zeus_android.sealed import open_envelope,b64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT=Path(os.environ['LAB_ACTIONS_PROOF']).resolve()
LAUNCH=json.loads(Path('experiments/actions-lab/launch.json').read_text())
CLOUDFLARED='https://github.com/cloudflare/cloudflared/releases/download/2026.10.6/cloudflared-linux-amd64'
DIGEST='1d356dac769d0dbf62ebe588c4034824bbff98d5790c2f844cc99e0e2f57462d'


def publish(sequence,directory,kind='artifact'):
    temp=ROOT/f'ready-{sequence}.tmp';temp.write_text(json.dumps({'sequence':sequence,'directory':directory.name,'kind':kind}));temp.chmod(0o644);temp.replace(ROOT/f'ready-{sequence}.json')

def encrypted_json(directory,name,value):
    directory.mkdir(exist_ok=True,mode=0o755)
    directory.chmod(0o755)
    path=directory/(name+'.sealed.json');path.write_text(json.dumps(seal(json.dumps(value).encode(),LAUNCH['public_key'],LAUNCH['session'])));path.chmod(0o644)

def clean_env(extra=None):
    return {**{k:os.environ[k] for k in ('PATH','HOME','LANG','NODE_PATH','CHROMIUM_PATH') if k in os.environ},**(extra or {})}


def checkpoint(data,directory,sequence,final,private):
    if LAUNCH.get('private_archive'):
        output=directory/f'archive-{sequence}';output.mkdir(mode=0o755,exist_ok=True);output.chmod(0o755)
        archive=output/f'checkpoint-{sequence:06d}.tar.gz'
        metadata=snapshot(data,archive,LAUNCH['session'],sequence,final);archive.chmod(0o644)
        metadata.update(owner=LAUNCH['owner'],conversation=LAUNCH['conversation'])
        (output/'manifest.json').write_text(json.dumps(metadata));(output/'manifest.json').chmod(0o644)
        publish(sequence,output,'private_release')
        return
    output=directory/f'checkpoint-{sequence}';output.mkdir(mode=0o755,exist_ok=True)
    output.chmod(0o755)
    with tempfile.TemporaryDirectory(dir=private) as temporary:
        temp=Path(temporary);db=sqlite3.connect(data/'state.sqlite3');snapshot=sqlite3.connect(temp/'state.sqlite3')
        db.backup(snapshot);snapshot.close();db.close();archive=temp/'checkpoint.tar.gz';total=0
        with tarfile.open(archive,'w:gz') as tar:
            for path in sorted(data.rglob('*')):
                if not path.is_file() or path.is_symlink() or path.name.startswith('state.sqlite3') or path.relative_to(data).parts[0]=='signing':continue
                total+=path.stat().st_size
                if total>25*1024*1024:raise ValueError('Acceptance checkpoint exceeds 25MiB plaintext limit')
                tar.add(path,arcname=str(path.relative_to(data)),recursive=False)
            tar.add(temp/'state.sqlite3',arcname='state.sqlite3',recursive=False)
        target=output/'session.zlab';metadata=seal_file(archive,target,LAUNCH['public_key'],LAUNCH['session'],maximum=20*1024*1024);target.chmod(0o644)
        encrypted_json(output,'manifest',{'archive':metadata,'final':final,'checkpoint_time':time.time(),'scope':'this controlled repository fixture session'})
    publish(sequence,output)


async def main():
    os.umask(0o077);ROOT.mkdir(exist_ok=True,mode=0o755)
    for name in ('session','owner','conversation'):uuid.UUID(LAUNCH[name])
    # RUNNER_TEMP's ancestors are private to the runner UID. Sandboxed APK
    # parsers need traversal to their own input/work directories, not access
    # to the runner home, checkout, credentials or control channel.
    private=Path(tempfile.mkdtemp(prefix='zeus-lab-private-',dir='/tmp'));private.chmod(0o711);data=private/'data';data.mkdir(exist_ok=True,mode=0o700)
    stop=asyncio.Event();loop=asyncio.get_running_loop()
    for signum in (signal.SIGTERM,signal.SIGINT):loop.add_signal_handler(signum,stop.set)
    deadline=time.time()+min(900,max(60,int(LAUNCH['runtime_seconds'])))
    bootstrap={'conversation':LAUNCH['conversation'],'viewer':secrets.token_urlsafe(40),'agent':secrets.token_urlsafe(40),'expires':deadline,'url':'','trusted':LAUNCH.get('trusted',False)}
    key=secrets.token_urlsafe(48);device=Device('emulator-5554');os.environ.update(ZEUS_ANDROID_EXTERNAL_AVD='1',ZEUS_ANDROID_TUNNEL='1',ZEUS_ANDROID_ACTIONS_RUNTIME='1')
    control_key=X25519PrivateKey.generate()
    control_private=control_key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
    control_public=b64(control_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
    control_file=ROOT.parent/'zeus-lab-control/incoming.json';control_sequence=0;seen_digest=''
    capture_token=secrets.token_urlsafe(40);os.environ['ZEUS_ANDROID_CAPTURE_TOKEN']=capture_token
    app=create_app(root=data,key=key,owner=LAUNCH['owner'],device=device,bootstrap=bootstrap)
    server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=8088,log_level='error',access_log=False,timeout_graceful_shutdown=5,ws_max_size=16384,ws_max_queue=4))
    emergency_task=None;observer=None;audit_test=None;serving=asyncio.create_task(server.serve());tunnel=None;log_file=None;result={'session':LAUNCH['session'],'fixture_only':LAUNCH.get('fixture_only',False),'credentials_published_plaintext':False,'status':'preparing'};code=0
    try:
        while not server.started:await asyncio.sleep(.05)
        observer=CaptureRuntime(private,data,device,capture_token,fixture=LAUNCH.get('fixture_only',False))
        certificate=await observer.start()
        await prepare_signing_key(data)
        try:
            provisioned=await install_interception_ca(device,certificate,data/'ca-provision.log')
            os.environ['ZEUS_ANDROID_CA_TRUST']='disposable_avd_system'
            result['network_proxy']={'available':True,'ca':provisioned}
        except (ValueError,OSError,asyncio.TimeoutError) as error:
            os.environ['ZEUS_ANDROID_CA_TRUST']='unavailable'
            result['network_proxy']={'available':True,'ca_error':str(error)[:1500],'https_guaranteed':False}
        deadline=time.time()+min(900,max(60,int(LAUNCH['runtime_seconds'])))
        bootstrap['expires']=deadline
        binary=private/'cloudflared' 
        def download():
            with urllib.request.urlopen(CLOUDFLARED,timeout=60) as response:raw=response.read(50*1024*1024)
            if len(raw)!=40275096 or hashlib.sha256(raw).hexdigest()!=DIGEST:raise ValueError('cloudflared verification failed')
            binary.write_bytes(raw);binary.chmod(0o755)
        try:await asyncio.to_thread(download)
        except (OSError,ValueError) as error:result['relay_setup_error']=type(error).__name__
        def viewer_headers():return {'Authorization':'Bearer '+encode(key,LAUNCH['owner'],LAUNCH['conversation'])}
        async with httpx.AsyncClient(base_url='http://127.0.0.1:8088',trust_env=False,timeout=120) as client:
            async def call(name,arguments):
                response=await client.post('/v1/tool',headers=viewer_headers(),json={'name':name,'arguments':arguments,'request_id':str(uuid.uuid4())})
                if response.status_code!=200:raise ValueError('Fixture operation failed: '+str(response.status_code)+' '+response.text[:1000])
                return response.json()
            await call('android_device',{'operation':'start'})
            project=None
            if LAUNCH.get('fixture_only',False):
                apk=Path(os.environ['LAB_PROBE_APK']).read_bytes();response=await client.post('/v1/upload',content=apk,headers={**viewer_headers(),'X-Filename':'zeus-ci-probe.apk','Content-Type':'application/vnd.android.package-archive'})
                response.raise_for_status();project=response.json()['id'];result['project']=project
                await call('android_project',{'operation':'install','project':project})
                await call('android_ui',{'operation':'launch','package':'com.zeus.lab.probe'})
                try:(data/'actual-initial-ui.json').write_text(json.dumps(await call('android_ui',{'operation':'tree'})))
                except ValueError as error:(data/'actual-initial-ui.json').write_text(json.dumps({'unavailable':str(error)}))
                await call('android_device',{'operation':'record_start','project':project,'kind':'logcat'})
                if LAUNCH.get('verify_network'):
                    result['actual_https_capture']=await verify_capture(call,device,observer,data)
                if LAUNCH.get('verify_static'):
                    async def verify_static():
                        job=await call('android_project',{'operation':'audit','project':project})
                        for _ in range(150):
                            state=await call('android_project',{'operation':'job','project':project,'job':job['id']})
                            if state['status']!='running':break
                            await asyncio.sleep(2)
                        if state['status']!='completed':raise ValueError('Actual isolated APK audit failed: '+str(state))
                        summary=await call('android_project',{'operation':'report','project':project})
                        if summary['inventory']['package']!='com.zeus.lab.probe':raise ValueError('Wrong actual APK report identity')
                        result['actual_static_audit']={'passed':True,'summary':summary}
                    audit_test=asyncio.create_task(verify_static())
                if LAUNCH.get('verify_rebuild'):
                    if audit_test:await audit_test
                    result['actual_rebuild']=await verify_rebuild(call,device,observer,data,project)
            if binary.is_file():
                logfile=private/'tunnel.log';log_file=logfile.open('wb')
                tunnel=subprocess.Popen([str(binary),'tunnel','--no-autoupdate','--url','http://127.0.0.1:8088','--protocol','http2'],stdout=log_file,stderr=log_file,env=clean_env(),start_new_session=True)
                for _ in range(100):
                    if tunnel.poll() is not None:break
                    matches=re.findall(r'https://[a-z0-9-]+\.trycloudflare\.com',logfile.read_text(errors='replace'))
                    if matches:bootstrap['url']=matches[-1];break
                    await asyncio.sleep(.5)
            fallback='https://github.com/'+os.environ.get('GITHUB_REPOSITORY','')+'/actions/runs/'+os.environ.get('GITHUB_RUN_ID','')
            access={'url':bootstrap['url']+'/lab/' if bootstrap['url'] else fallback,'tunnel_available':bool(bootstrap['url']),'session':LAUNCH['session'],'owner':LAUNCH['owner'],'conversation':LAUNCH['conversation'],'viewer_bootstrap':bootstrap['viewer'],'agent_bootstrap':bootstrap['agent'],'deadline':deadline,'project':project,'transport':'websocket','control_public_key':control_public,'control_path':'experiments/actions-lab/control.json'}
            encrypted_json(ROOT/'connection','connection',access);publish(0,ROOT/'connection')
            await asyncio.to_thread(checkpoint,data,ROOT,1,False,private)
            result.update(status='ready',actual_android_api=(await device.command('shell','getprop','ro.build.version.sdk')).decode().strip())
            async def test_relay():
                # Ordinary readiness only: denied destinations are never retried.
                healthy=False
                async with httpx.AsyncClient(timeout=8,follow_redirects=False) as probe:
                    for _ in range(12 if bootstrap['url'] else 0):
                        try:
                            check=await probe.get(bootstrap['url']+'/health')
                            if check.status_code==200:healthy=True;break
                            if check.status_code in (401,403):result['tunnel_probe_status']=check.status_code;break
                        except httpx.HTTPError:pass
                        await asyncio.sleep(2)
                result['tunnel_healthy']=healthy
                if healthy:
                    live_token=encode(key,LAUNCH['owner'],LAUNCH['conversation'])
                    env=clean_env({'LAB_LIVE_URL':bootstrap['url']+'/lab/','LAB_LIVE_TOKEN':live_token,'LAB_LIVE_PROJECT':project,'LAB_PROOF_DIR':str(data)})
                    browser=await asyncio.create_subprocess_exec('node','AndroidLab/actions/tunnel_browser.cjs',env=env,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT)
                    try:
                        async with asyncio.timeout(80):browser_log,_=await browser.communicate()
                    except asyncio.TimeoutError:browser.kill();await browser.wait();browser_log=b'Browser timeout'
                    (data/'browser.log').write_bytes(browser_log.replace(live_token.encode(),b'[redacted]'))
                    result['browser_passed']=browser.returncode==0
                else:result['browser_passed']=False;result['browser_error']='Temporary relay was not reachable; GitHub artifact control remains available'
                await asyncio.to_thread(checkpoint,data,ROOT,2,False,private)
                print('LAB_RELAY_TEST browser_passed='+str(result['browser_passed']),flush=True)
            relay_test=asyncio.create_task(test_relay()) if LAUNCH.get('fixture_only',False) else asyncio.create_task(asyncio.sleep(0))
            frames=0;frame_bytes=0;next_frame=0;previous_frame='';last_published_frame=0;network_cursor=0;network_window=[]
            archive_sequence=10;next_archive=time.time()+120
            def emergency_publish(number,value):
                destination=ROOT/f'emergency-{number}';encrypted_json(destination,'emergency',value);publish(200000+number,destination)
            mailbox=EmergencyMailbox(control_file.with_name('emergency.json'),LAUNCH['session'],control_private,bootstrap['viewer'],
                lambda:encode(key,LAUNCH['owner'],LAUNCH['conversation'],'viewer'),client,emergency_publish,
                lambda value:(data/'emergency-error.json').write_text(json.dumps(value)))
            emergency_task=asyncio.create_task(mailbox.run(stop,deadline))
            print('LAB_ACCEPTANCE_READY',flush=True)
            while time.time()<deadline and not stop.is_set():
                if LAUNCH.get('private_archive') and time.time()>=next_archive:
                    next_archive=time.time()+120
                    if not app.state.projects.tasks:
                        try:
                            await asyncio.to_thread(checkpoint,data,ROOT,archive_sequence,False,private)
                            archive_sequence+=1
                        except (ValueError,OSError) as error:
                            (data/'archive-error.json').write_text(json.dumps({'detail':str(error)[:1000]}))
                if observer and observer.process.returncode is not None:
                    os.environ['ZEUS_ANDROID_CAPTURE_READY']='0'
                    current=app.state.lab.load()
                    if current and current.get('capture'):
                        current['capture']=False;app.state.lab.save(current)
                        app.state.lab.record(current['scope'],'network_observer_stopped',{'reason':'observer_process_exited'})
                if time.time()>=next_frame and frame_bytes<15*1024*1024:
                    next_frame=time.time()+8
                    try:
                        frame=await device.screenshot()
                        network=await call('android_network',{'operation':'list','after':network_cursor,'limit':50})
                        network_cursor=max([network_cursor,*[e['id'] for e in network['events']]])
                        network_window=(network_window+network['events'])[-100:]
                        snapshot={'state':app.state.lab.load(),'network':{'events':network_window}}
                        fingerprint=hashlib.sha256(frame+json.dumps(snapshot,sort_keys=True).encode()).hexdigest()
                        if fingerprint!=previous_frame or time.time()-last_published_frame>=24:
                            frames+=1;frame_bytes+=len(frame);previous_frame=fingerprint;last_published_frame=time.time()
                            destination=ROOT/f'frame-{frames}'
                            encrypted_json(destination,'frame',{'session':LAUNCH['session'],'frame':frames,'observed_at':time.time(),'screenshot':b64(frame),'kind':'successive_screenshots','live_video':False,**snapshot})
                            publish(1000+frames,destination)
                            (data/'latest-frame.json').write_text(json.dumps({'frame':frames,'observed_at':time.time(),'screenshot':b64(frame)}))
                    except (ValueError,OSError,asyncio.TimeoutError):pass
                if control_file.exists():
                    raw=control_file.read_bytes();digest=hashlib.sha256(raw).hexdigest()
                    if digest!=seen_digest:
                        seen_digest=digest
                        accepted=False
                        try:
                            outer=json.loads(raw)
                            if outer.get('sequence')==0 and not outer.get('payload'):continue
                            if outer.get('session')!=LAUNCH['session'] or outer.get('sequence')!=control_sequence+1:raise ValueError('Control is out of sequence')
                            command=json.loads(open_envelope(outer['payload'],control_private))
                            credential=command.get('credential','');role=next((r for r in ('viewer','agent') if __import__('hmac').compare_digest(credential,bootstrap[r])),None)
                            if role is None:raise ValueError('Control credential is invalid')
                            name=command.get('name');arguments=command.get('arguments',{});request_id=str(uuid.UUID(command['request_id']))
                            accepted=True
                            headers={'Authorization':'Bearer '+encode(key,LAUNCH['owner'],LAUNCH['conversation'],role)}
                            if name=='__take':
                                if role!='viewer':raise ValueError('Only the viewer can reclaim control')
                                response=await client.post('/v1/control/take',headers=headers,json={})
                            elif name=='__heartbeat':response=await client.post('/v1/heartbeat',headers=headers,json={})
                            elif name=='__upload':
                                if role!='viewer':raise ValueError('Only the viewer can import an APK release asset')
                                with tempfile.TemporaryDirectory(dir=private) as temporary:
                                    incoming=Path(temporary)/'incoming.apk'
                                    await download_asset(arguments.get('url'),arguments.get('sha256'),incoming,MAX_APK)
                                    async def chunks():
                                        with incoming.open('rb') as source:
                                            while block:=source.read(256*1024):yield block
                                    filename=Path(str(arguments.get('filename','application.apk'))).name
                                    response=await client.post('/v1/upload',headers={**viewer_headers(),'X-Filename':quote(filename,safe=''),'Content-Type':'application/vnd.android.package-archive'},content=chunks())
                            elif name=='__restore':
                                if role!='viewer':raise ValueError('Only the viewer can restore a saved project')
                                if app.state.projects.tasks:raise ValueError('Wait for the active APK job before restoring projects')
                                with tempfile.TemporaryDirectory(dir=private) as temporary:
                                    incoming=Path(temporary)/'checkpoint.tar.gz'
                                    await download_asset(arguments.get('url'),arguments.get('sha256'),incoming,MAX_ARCHIVE)
                                    scope=app.state.lab.scope({'sub':LAUNCH['owner'],'conversation':LAUNCH['conversation']})
                                    restored=await asyncio.to_thread(restore_projects,incoming,app.state.projects,scope)
                                    app.state.lab.record(scope,'projects_restored',{'actor':'viewer','projects':[p['id'] for p in restored['projects']]})
                                    response=httpx.Response(200,json=restored)
                            elif name=='__export':
                                if role!='viewer':raise ValueError('Only the viewer can export project evidence')
                                project=str(uuid.UUID(arguments.get('project','')));format=arguments.get('format','json');variant=arguments.get('variant','original')
                                if format not in {'json','html','pdf'} or variant not in {'original','rebuilt'}:raise ValueError('Unknown report format or APK variant')
                                exported=await client.get('/v1/projects/'+project+'/export',params={'format':format,'variant':variant},headers=viewer_headers())
                                if exported.status_code!=200:response=exported
                                else:
                                    if len(exported.content)>2*1024*1024:raise ValueError('This report exceeds the 2 MiB sealed sharing limit; its project archive remains available')
                                    response=httpx.Response(200,json={'filename':'ZEUS-Report.'+format,'content':b64(exported.content),'sha256':hashlib.sha256(exported.content).hexdigest()})
                            else:response=await client.post('/v1/tool',headers=headers,json={'name':name,'arguments':arguments,'request_id':request_id})
                            try:response_body=response.json()
                            except ValueError:response_body={'detail':'Worker returned a non-JSON response','uncertain':True}
                            control_sequence=outer['sequence'];observation={'sequence':control_sequence,'request_id':request_id,'http_status':response.status_code,'result':response_body,'observed_at':time.time(),'session':app.state.lab.load()}
                            if name not in {'__export','__upload','__restore'} and (app.state.lab.load() or {}).get('status')=='running':
                                observation['screenshot']=b64(await device.screenshot())
                                try:observation['tree']=await device.action('tree',{})
                                except ValueError as error:observation['tree']={'unavailable':str(error)}
                            destination=ROOT/f'observation-{control_sequence}';encrypted_json(destination,'observation',observation);publish(100+control_sequence,destination)
                            (data/f'observation-{control_sequence}.json').write_text(json.dumps(observation))
                            result['github_control_verified']=True
                        except Exception as error:
                            (data/'control-error.json').write_text(json.dumps({'error':type(error).__name__,'detail':str(error)[:1000]}))
                            if accepted:
                                control_sequence=outer['sequence']
                                observation={'sequence':control_sequence,'request_id':request_id,'http_status':400,
                                    'result':{'detail':str(error)[:1000],'uncertain':not isinstance(error,ValueError)},'observed_at':time.time(),'session':app.state.lab.load()}
                                destination=ROOT/f'observation-{control_sequence}';encrypted_json(destination,'observation',observation);publish(100+control_sequence,destination)
                if LAUNCH.get('acceptance_auto_end') and relay_test.done() and (audit_test is None or audit_test.done()):
                    await relay_test
                    if audit_test:await audit_test
                    await call('android_device',{'operation':'stop'})
                saved=app.state.lab.load()
                if saved and saved['status']=='stopped':result['ended']='user_stop';break
                try:await asyncio.wait_for(stop.wait(),2)
                except asyncio.TimeoutError:pass
            else:result['ended']='deadline_or_signal'
            if not relay_test.done():relay_test.cancel()
            await asyncio.gather(relay_test,return_exceptions=True)
            result.update(successive_frames=frames,frame_bytes=frame_bytes)
            result['status']='completed' if result.get('browser_passed') else 'artifact_control_verified' if result.get('github_control_verified') else 'static_audit_verified' if result.get('actual_static_audit',{}).get('passed') and not LAUNCH.get('require_relay',True) else 'transport_not_verified'
            if result['status']=='transport_not_verified':code=1
    except BaseException as error:
        code=1;result.update(status='failed',error=type(error).__name__,detail=str(error)[:3000])
    finally:
        if audit_test and not audit_test.done():audit_test.cancel();await asyncio.gather(audit_test,return_exceptions=True)
        (data/'result.json').write_text(json.dumps(result,indent=2))
        encrypted_json(ROOT/'result','result',result);publish(97,ROOT/'result')
        if emergency_task:emergency_task.cancel();await asyncio.gather(emergency_task,return_exceptions=True)
        if observer:await observer.close()
        server.should_exit=True
        try:await asyncio.wait_for(serving,10)
        except asyncio.TimeoutError:serving.cancel();await asyncio.gather(serving,return_exceptions=True)
        try:await asyncio.to_thread(checkpoint,data,ROOT,99,True,private)
        except Exception as error:
            encrypted_json(ROOT/'failed-checkpoint','failure',{'error':type(error).__name__,'detail':str(error)[:1000]});publish(98,ROOT/'failed-checkpoint');code=1
        if tunnel and tunnel.poll() is None:
            os.killpg(tunnel.pid,signal.SIGKILL);tunnel.wait()
        if log_file:log_file.close()
        print('LAB_SESSION_ENDED status='+result['status'],flush=True)
    return code

if __name__=='__main__':raise SystemExit(asyncio.run(main()))
