import asyncio
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid
import zipfile
import httpx
from zeus_android.app import create_app
from zeus_android.tokens import encode, decode
from zeus_android.projects import Projects
from zeus_android.device import Device

KEY="test-signing-key-not-a-production-credential-0000"
OWNER="owner"


class DeviceFixture:
    def __init__(self): self.calls=[]
    async def connect(self): self.calls.append(("connect",))
    async def command(self,*args,**kwargs): self.calls.append(args); return b"Success"
    async def action(self,op,args): self.calls.append((op,args)); return {"executed":op}
    async def screenshot(self): return b"fixture-image"


class LabTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        environment=patch.dict('os.environ',{'ZEUS_ANDROID_EXTERNAL_AVD':'1'});environment.start();self.addCleanup(environment.stop)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.device=DeviceFixture();self.now=10000;self.conversation=str(uuid.uuid4())
        self.app=create_app(root=self.temp.name,key=KEY,owner=OWNER,device=self.device,clock=lambda:self.now)
        self.life=self.app.router.lifespan_context(self.app);await self.life.__aenter__();self.addAsyncCleanup(self.life.__aexit__,None,None,None)
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),base_url="https://lab.test")
        self.addAsyncCleanup(self.client.aclose)
    def auth(self,role="viewer",conversation=None,owner=OWNER):return {"Authorization":"Bearer "+encode(KEY,owner,conversation or self.conversation,role,now=self.now)}
    async def call(self,name,args=None,role="viewer",identifier=None,conversation=None):
        return await self.client.post('/v1/tool',headers=self.auth(role,conversation),json={"name":name,"arguments":args or {},"request_id":identifier or str(uuid.uuid4())})
    async def start(self):
        r=await self.call('android_device',{'operation':'start'});self.assertEqual(r.status_code,200,r.text)
    async def test_access_is_expiring_owner_and_conversation_scoped(self):
        self.assertEqual((await self.client.get('/v1/session')).status_code,401)
        self.assertEqual((await self.client.get('/v1/session',headers=self.auth(owner='other'))).status_code,403)
        await self.start()
        r=await self.call('android_device',{'operation':'start'},conversation=str(uuid.uuid4()))
        self.assertEqual(r.status_code,400)
        token=encode(KEY,OWNER,self.conversation,now=self.now);self.now+=301
        self.assertEqual((await self.client.get('/v1/session',headers={'Authorization':'Bearer '+token})).status_code,401)
    async def test_manual_takeover_blocks_agent_actions_but_allows_observation(self):
        await self.start()
        r=await self.call('android_ui',{'operation':'tap','x':.5,'y':.5},role='agent');self.assertEqual(r.status_code,400)
        self.assertEqual((await self.call('android_ui',{'operation':'tree'},role='agent')).status_code,200)
        await self.call('android_device',{'operation':'release'})
        self.assertEqual((await self.call('android_ui',{'operation':'tap','x':.5,'y':.5},role='agent')).status_code,200)
        await self.call('android_device',{'operation':'take'})
        self.assertEqual((await self.call('android_ui',{'operation':'tap','x':.5,'y':.5},role='agent')).status_code,400)
    async def test_mutations_are_idempotent_and_changed_ids_are_rejected(self):
        await self.start();identifier=str(uuid.uuid4());args={'operation':'tap','x':.5,'y':.5}
        a=await self.call('android_ui',args,identifier=identifier);b=await self.call('android_ui',args,identifier=identifier)
        self.assertEqual(a.json(),b.json());self.assertEqual(sum(c[0]=='tap' for c in self.device.calls),1)
        r=await self.call('android_ui',{**args,'x':.1},identifier=identifier);self.assertEqual(r.status_code,400)
    async def test_agent_cannot_start_a_billable_device_or_transfer_control(self):
        r=await self.call('android_device',{'operation':'start'},role='agent');self.assertEqual(r.status_code,400)
        self.assertEqual(self.device.calls,[])
        await self.start();await self.call('android_device',{'operation':'release'})
        r=await self.call('android_device',{'operation':'take'},role='agent');self.assertEqual(r.status_code,400)
    async def test_hard_deadline_cannot_be_extended_by_heartbeats(self):
        await self.start();self.now+=1799
        r=await self.client.post('/v1/heartbeat',headers=self.auth());self.assertEqual(r.json()['deadline'],11800)
        self.now+=2;r=await self.call('android_ui',{'operation':'tree'})
        self.assertEqual(r.status_code,400);self.assertEqual(self.app.state.lab.load()['status'],'stopped')
    async def test_upload_preserves_original_and_rejects_archive_traversal(self):
        def apk(unsafe=False):
            output=io.BytesIO()
            with zipfile.ZipFile(output,'w') as z:
                z.writestr('AndroidManifest.xml',b'manifest');z.writestr('../bad' if unsafe else 'classes.dex',b'dex')
            return output.getvalue()
        bad=await self.client.post('/v1/upload',headers=self.auth(),content=apk(True));self.assertEqual(bad.status_code,400)
        good=await self.client.post('/v1/upload',headers=self.auth(),content=apk());self.assertEqual(good.status_code,200,good.text)
        p=self.app.state.lab.root/'projects'/self.app.state.lab.scope(decode(KEY,self.auth()['Authorization'][7:],now=self.now))/good.json()['id']/'original.apk'
        self.assertEqual(p.read_bytes(),apk());self.assertEqual(good.json()['sha256'],hashlib.sha256(apk()).hexdigest())
        other=await self.call('android_project',{'operation':'list'},conversation=str(uuid.uuid4()));self.assertEqual(other.json()['projects'],[])
    async def test_failed_mutation_is_not_replayed_after_an_uncertain_result(self):
        await self.start()
        async def failure(*a):raise ValueError('lost connection')
        self.device.action=failure;identifier=str(uuid.uuid4())
        first=await self.call('android_ui',{'operation':'tap','x':.1,'y':.1},identifier=identifier)
        second=await self.call('android_ui',{'operation':'tap','x':.1,'y':.1},identifier=identifier)
        self.assertEqual(first.status_code,400);self.assertIn('interrupted',second.json()['detail'])
    async def test_capture_cannot_cross_conversation_and_is_bounded(self):
        state=self.app.state.lab
        for i in range(1050):state.capture('a',{'url':str(i)})
        self.assertEqual(state.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],1000)
        self.assertEqual(state.events('other'),[])
        self.assertEqual(len(state.events('a')),50)
    async def test_static_page_has_no_caching_inline_script_or_token_query(self):
        r=await self.client.get('/lab/')
        self.assertEqual(r.status_code,200);self.assertEqual(r.headers['cache-control'],'no-store')
        self.assertNotIn("'unsafe-inline'",r.headers['content-security-policy'])
        self.assertIn('playsinline',r.text)
        self.assertEqual((await self.client.get('/lab/../../tokens.py')).status_code,404)

    async def test_delete_removes_only_this_conversations_projects_and_capture(self):
        await self.start();scope=self.app.state.lab.load()['scope']
        root=self.app.state.lab.root/'projects'/scope;root.mkdir(parents=True);(root/'private-apk.bin').write_bytes(b'mine')
        other=self.app.state.lab.root/'projects'/'other';other.mkdir();(other/'keep').write_bytes(b'other')
        self.app.state.lab.capture(scope,{'url':'private'})
        response=await self.client.delete('/v1/session',headers=self.auth())
        self.assertEqual(response.status_code,200,response.text);self.assertFalse(root.exists())
        self.assertEqual((other/'keep').read_bytes(),b'other');self.assertEqual(self.app.state.lab.events(scope),[])
        self.assertIsNone(self.app.state.lab.load())

    async def test_capture_requires_private_key_and_rejects_pre_session_flows(self):
        environment=patch.dict('os.environ',{'ZEUS_ANDROID_CAPTURE_TOKEN':'c'*40});environment.start();self.addCleanup(environment.stop)
        await self.start();await self.call('android_network',{'operation':'start'})
        self.assertEqual((await self.client.post('/internal/capture',json={'started':self.now})).status_code,403)
        headers={'X-Capture-Token':'c'*40}
        response=await self.client.post('/internal/capture',headers=headers,json={'started':self.now-1,'url':'old'})
        self.assertFalse(response.json()['accepted'])
        response=await self.client.post('/internal/capture',headers=headers,json={'started':self.now,'url':'new'})
        self.assertTrue(response.json()['accepted'])

    async def test_actions_capture_cannot_claim_success_without_a_running_observer(self):
        await self.start()
        with patch.dict('os.environ',{'ZEUS_ANDROID_ACTIONS_RUNTIME':'1','ZEUS_ANDROID_CAPTURE_READY':'0'}):
            response=await self.call('android_network',{'operation':'start'})
        self.assertEqual(response.status_code,400)
        self.assertFalse(self.app.state.lab.load()['capture'])
        proxy_calls=[c for c in self.device.calls if 'http_proxy' in c]
        self.assertTrue(all(c[-1]==':0' for c in proxy_calls))


class DeviceTests(unittest.IsolatedAsyncioTestCase):
    async def test_tree_retries_incomplete_boot_output_without_reusing_old_file(self):
        device=Device('emulator-5554');calls=[];reads=0
        async def command(*args,**kw):
            nonlocal reads
            calls.append(args)
            if args[:2]==('exec-out','cat'):
                reads+=1
                return b'ERROR: screen changing' if reads==1 else b'<hierarchy><node text="Settings" password="false"/></hierarchy>'
            return b''
        device.command=command
        result=await device.action('tree',{})
        self.assertEqual(result['nodes'][0]['text'],'Settings')
        self.assertEqual(sum(c[:3]==('shell','rm','-f') for c in calls),2)
        self.assertTrue(all('/sdcard/' not in str(c) for c in calls))

    async def test_invalid_ui_tree_is_a_controlled_error(self):
        device=Device('emulator-5554')
        async def command(*args,**kw):return b'not xml'
        device.command=command
        with self.assertRaisesRegex(ValueError,'valid UI hierarchy'):await device.action('tree',{})

    async def test_waits_for_ime_readiness_before_a_single_text_mutation(self):
        device=Device('emulator-5554');calls=[];ready=0
        async def command(*args,**kw):
            nonlocal ready
            calls.append(args)
            if 'com.zeus.lab.READY' in args:
                ready+=1;return b'Broadcast completed: result='+ (b'1' if ready>=3 else b'0')
            return b'Broadcast completed: result=1'
        device.command=command
        await device.action('type',{'text':'one message'})
        self.assertEqual(ready,3)
        self.assertEqual(sum('com.zeus.lab.INPUT' in c for c in calls),1)
        self.assertEqual(sum(c[:3]==('shell','ime','set') for c in calls),1)

    async def test_arbitrary_package_and_non_normalized_coordinates_never_reach_adb(self):
        device=Device('emulator-5554')
        for args in [{'package':'good.app; id'}, {'package':'$(id)'}, {'package':'../app'}]:
            with self.assertRaises(ValueError):await device.action('launch',args)
        with self.assertRaises(ValueError):Device('host;id')
    async def test_unicode_input_is_base64_and_not_shell_interpolation(self):
        device=Device('emulator-5554');calls=[]
        async def command(*args,**kw):calls.append(args);return b'Broadcast completed: result=1'
        device.command=command
        text='مرحبا $(id); "hello"'
        await device.action('type',{'text':text})
        mutation=next(c for c in calls if 'payload' in c)
        self.assertNotIn(text,mutation);self.assertEqual(base64.b64decode(mutation[-1]).decode(),text)


if __name__=='__main__':unittest.main()
