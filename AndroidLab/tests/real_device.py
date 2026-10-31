"""Opt-in CI smoke against a real booted Android AVD; never runs in unit tests."""
import asyncio
import base64
import json
import os
import hashlib
import re
import secrets
import subprocess
from pathlib import Path
import tempfile
import uuid
import httpx
import uvicorn
from aiortc import RTCPeerConnection,RTCConfiguration,RTCSessionDescription
from zeus_android.device import Device
from zeus_android.app import create_app
from zeus_android.tokens import encode
from tls_origin import start_origin,install_interception_ca


async def main():
    os.environ['ZEUS_ANDROID_EXTERNAL_AVD']='1'
    device=Device(os.environ.get('ZEUS_ANDROID_ADB','emulator-5554'))
    with tempfile.TemporaryDirectory() as directory:
        key='ci-only-not-a-production-signing-key-0000000';owner='ci-test';conversation=str(uuid.uuid4())
        app=create_app(root=directory,key=key,owner=owner,device=device)
        proof=Path(os.environ.get('LAB_PROOF_DIR','android-results'));proof.mkdir(exist_ok=True)
        server=uvicorn.Server(uvicorn.Config(app,lifespan='off',host='127.0.0.1',port=8088,log_level='warning',access_log=False))
        serving=asyncio.create_task(server.serve())
        origin,origin_ca=start_origin(directory,hold=True)
        capture_token=secrets.token_urlsafe(40);os.environ['ZEUS_ANDROID_CAPTURE_TOKEN']=capture_token
        capture_log=(proof/'capture.log').open('w')
        ca_directory=Path(directory)/'capture-ca'
        capture=subprocess.Popen([os.environ['LAB_CAPTURE_EXE'],'--listen-host','0.0.0.0','--listen-port','8089','--set','connection_strategy=lazy','--set','confdir='+str(ca_directory),'--set','ssl_verify_upstream_trusted_ca='+str(origin_ca),'-s','AndroidLab/tests/route_probe.py','-s','AndroidLab/zeus_android/capture.py'],
            env={**os.environ,'ZEUS_ANDROID_CAPTURE_ENDPOINT':'http://127.0.0.1:8088/internal/capture'},stdout=capture_log,stderr=capture_log)
        async with app.router.lifespan_context(app),httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://lab.test',headers={'Authorization':'Bearer '+encode(key,owner,conversation)}) as client:
            async def call(name,args):
                response=await client.post('/v1/tool',json={'name':name,'arguments':args,'request_id':str(uuid.uuid4())})
                assert response.status_code==200,response.text
                return response.json()
            async def job(project,operation):
                value=await call('android_project',{'operation':operation,'project':project})
                for _ in range(310):
                    result=await call('android_project',{'operation':'job','project':project,'job':value['id']})
                    if result['status']!='running':assert result['status']=='completed',result;return result
                    await asyncio.sleep(2)
                raise AssertionError('APK job did not finish')
            for _ in range(100):
                if (ca_directory/'mitmproxy-ca-cert.pem').is_file(): break
                await asyncio.sleep(.1)
            await install_interception_ca(device,ca_directory/'mitmproxy-ca-cert.pem',proof/'android-ca-setup.log')
            # Base-image provisioning precedes session startup; the actual
            # startup then installs/selects the keyboard after the reboot.
            await call('android_device',{'operation':'start'})
            await call('android_ui',{'operation':'launch','package':'com.android.settings'})
            tree=await call('android_ui',{'operation':'tree'});assert tree['nodes']
            screenshot=await call('android_screenshot',{});data=base64.b64decode(screenshot['image']['data']);assert data[:2]==b'\xff\xd8'
            (proof/'actual-android-settings.jpg').write_bytes(data)
            (proof/'actual-android-ui-tree.json').write_text(json.dumps(tree,ensure_ascii=False))
            await call('android_ui',{'operation':'key','key':'home'})
            await call('android_network',{'operation':'start'})
            configured=(await device.command('shell','settings','get','global','http_proxy')).decode().strip()
            assert configured==os.environ.get('ZEUS_ANDROID_PROXY','capture:8080'),configured
            apk=Path(os.environ['LAB_PROBE_APK']).read_bytes()
            uploaded=await client.post('/v1/upload',content=apk,headers={'X-Filename':'zeus-probe.apk'})
            assert uploaded.status_code==200,uploaded.text
            project=uploaded.json()['id'];assert uploaded.json()['sha256']==hashlib.sha256(apk).hexdigest()
            await call('android_project',{'operation':'install','project':project})
            await call('android_ui',{'operation':'launch','package':'com.zeus.lab.probe'})
            await asyncio.sleep(1)
            tree=await call('android_ui',{'operation':'tree'})
            width,height=await device.size()
            def point(description):
                node=next(n for n in tree['nodes'] if n.get('content-desc')==description)
                left,top,right,bottom=map(int,re.findall(r'\d+',node['bounds']))
                return {'x':(left+right)/2/width,'y':(top+bottom)/2/height}
            await call('android_ui',{'operation':'tap',**point('probeInput')})
            (proof/'before-type-ui.json').write_text(json.dumps(await call('android_ui',{'operation':'tree'}),ensure_ascii=False))
            (proof/'before-type.jpg').write_bytes(await device.screenshot())
            (proof/'before-type-ime.txt').write_bytes(await device.command('shell','dumpsys','input_method'))
            (proof/'before-type-ime-ready.txt').write_bytes(await device.command('shell','am','broadcast','-a','com.zeus.lab.READY','-p','com.zeus.lab.ime'))
            (proof/'before-type-ime-ready-unscoped.txt').write_bytes(await device.command('shell','am','broadcast','-a','com.zeus.lab.READY'))
            try:await call('android_ui',{'operation':'type','text':'مرحبا ZEUS probe'})
            finally:
                (proof/'after-type-ime.txt').write_bytes(await device.command('shell','dumpsys','input_method'))
                (proof/'ime-runtime-errors.txt').write_bytes(await device.command('logcat','-d','-t','150','AndroidRuntime:E','*:S'))
            # Keyboard appearance can move the button; reread actual bounds.
            tree=await call('android_ui',{'operation':'tree'})
            await call('android_ui',{'operation':'tap',**point('probeSend')})
            found=None
            for _ in range(50):
                events=(await call('android_network',{'operation':'read','after':0}))['events']
                found=next((e for e in events if e['url'].endswith('/probe')),None)
                if found:break
                await asyncio.sleep(.2)
            if found is None:
                (proof/'after-send-ui.json').write_text(json.dumps(await call('android_ui',{'operation':'tree'}),ensure_ascii=False))
                (proof/'after-send.jpg').write_bytes(await device.screenshot())
            assert found is not None,'Actual Android request did not reach capture addon'
            assert base64.b64decode(found['request_body']['base64']).decode()=='مرحبا ZEUS probe',found
            assert found['phase']=='request' and not origin.replied.is_set(),'Capture waited for the full response'
            (proof/'actual-request-before-response.json').write_text(json.dumps(found,ensure_ascii=False,indent=2))
            origin.release.set();cursor=found['id']
            for _ in range(50):
                events=(await call('android_network',{'operation':'read','after':cursor}))['events']
                if events:
                    found=events[0];cursor=found['id']
                    if found.get('phase')=='complete':break
                await asyncio.sleep(.2)
            assert found['phase']=='complete',found
            assert found['status']==200,found
            assert found['url'].startswith('https://'),found
            (proof/'actual-android-captured-request.json').write_text(json.dumps(found,ensure_ascii=False,indent=2))
            peer=RTCPeerConnection(RTCConfiguration(iceServers=[]));frame_ready=asyncio.Future()
            @peer.on('track')
            def on_track(track):
                async def receive():
                    try:
                        frame=await track.recv()
                        if not frame_ready.done():frame_ready.set_result(frame)
                    except Exception as e:
                        if not frame_ready.done():frame_ready.set_exception(e)
                asyncio.create_task(receive())
            try:
                peer.addTransceiver('video',direction='recvonly');await peer.setLocalDescription(await peer.createOffer())
                offered=await client.post('/v1/video',json={'sdp':peer.localDescription.sdp,'type':peer.localDescription.type})
                assert offered.status_code==200,offered.text
                await peer.setRemoteDescription(RTCSessionDescription(**offered.json()))
                frame=await asyncio.wait_for(frame_ready,25);assert frame.width>0 and frame.height>0
                frame.to_image().save(proof/'actual-android-video-frame.jpg')
            finally:await peer.close()
            browser_token=encode(key,owner,conversation)
            browser=await asyncio.create_subprocess_exec('node','AndroidLab/tests/browser_device.cjs',
                env={**os.environ,'LAB_TEST_TOKEN':browser_token,'LAB_PROOF_DIR':str(proof.resolve())})
            assert await browser.wait()==0,'Actual browser video preview failed'
            await job(project,'analyze')
            sources=await call('android_project',{'operation':'files','project':project,'tree':'sources'})
            assert any(p.endswith('/Probe.java') for p in sources['files']),sources
            await job(project,'decode')
            manifest=await call('android_project',{'operation':'read','project':project,'path':'AndroidManifest.xml'})
            assert 'ZEUS CI Probe' in manifest['content'],manifest['content']
            await call('android_project',{'operation':'write','project':project,'path':'AndroidManifest.xml','content':manifest['content'].replace('ZEUS CI Probe','ZEUS CI Edited'),'expected_sha256':manifest['sha256']})
            keyfile=Path(directory)/'lab.keystore'
            subprocess.run(['keytool','-genkeypair','-alias','zeus-lab','-keyalg','RSA','-keystore',str(keyfile),'-storepass','android','-keypass','android','-dname','CN=ZEUS CI','-validity','3'],check=True,capture_output=True)
            os.environ['ZEUS_ANDROID_KEYSTORE']=str(keyfile)
            built=await job(project,'build');(proof/'actual-apk-build.json').write_text(json.dumps(built,indent=2))
            scope=app.state.lab.load()['scope'];project_root=Path(directory)/'projects'/scope/project
            assert hashlib.sha256((project_root/'original.apk').read_bytes()).hexdigest()==uploaded.json()['sha256']
            assert hashlib.sha256((project_root/'rebuilt.apk').read_bytes()).hexdigest()!=uploaded.json()['sha256']
            await device.command('uninstall','com.zeus.lab.probe')  # Only the controlled CI fixture.
            await call('android_project',{'operation':'install','project':project,'variant':'rebuilt'})
            await call('android_ui',{'operation':'launch','package':'com.zeus.lab.probe'})
            await call('android_network',{'operation':'stop'})
            await call('android_device',{'operation':'stop'})
            server.should_exit=True;await serving;origin.shutdown();origin.server_close();capture.terminate();capture.wait(timeout=5);capture_log.close()
            print('PASS: actual Android launch/UI/screenshot/Unicode input, controlled HTTPS capture with trusted CA, H264-WebRTC frame, JADX analysis, APK decode/edit/build/re-sign/install; original digest preserved. Third-party pinning and cellular WebRTC are not inferred.')


if __name__=='__main__':asyncio.run(main())
