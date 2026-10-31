import hashlib
import asyncio
import time
import io
import json
from pathlib import Path
import tempfile
import unittest
import uuid
import zipfile
from zeus_android import audit,reports
import test_lab as lab_fixture

MANIFEST='''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.lab" android:versionName="1"><uses-sdk android:minSdkVersion="29" android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/><application android:debuggable="true"><activity android:name=".Public" android:exported="true"/><service android:name=".Private" android:exported="false"/></application></manifest>'''


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.decoded=self.root/'decoded';self.sources=self.root/'sources';self.decoded.mkdir();self.sources.mkdir()
        (self.decoded/'AndroidManifest.xml').write_text(MANIFEST)
        (self.sources/'Network.java').write_text('import okhttp3.Request;\nString url="https://api.example.test/send?api_key=secret";\nweb.setJavaScriptEnabled(true);\n')
        self.apk=self.root/'original.apk'
        with zipfile.ZipFile(self.apk,'w') as z:z.writestr('classes.dex',b'dex\n035\x00');z.writestr('lib/arm64-v8a/libtest.so',b'library')
    def report(self):return audit.analyze(self.apk,self.decoded,self.sources,{'id':'test'})
    def test_inventory_uses_explicit_manifest_evidence_and_never_confirms_an_exploit(self):
        report=self.report();self.assertEqual(report['inventory']['package'],'test.lab')
        self.assertEqual(len(report['dex']),1);self.assertEqual(report['native_libraries'][0]['bytes'],7)
        self.assertEqual(report['coverage']['confirmed_vulnerabilities'],0)
        self.assertEqual({f['classification'] for f in report['findings']},{'observation','unresolved'})
        index=report['source_observations'];self.assertEqual(index['endpoints'][0]['endpoint'],'https://api.example.test/send')
        self.assertNotIn('secret',json.dumps(report));self.assertTrue(index['matches'][0]['sha256'])
    def test_source_search_reports_line_and_hash_without_following_symlinks(self):
        (self.sources/'escape.java').symlink_to('/etc/passwd')
        found=audit.source_index({'sources':self.sources},'setJavaScriptEnabled')
        self.assertEqual(found['matches'][0]['line'],3);self.assertEqual(found['coverage']['files_scanned'],1)
        (self.sources/'malformed.java').write_text('String url="https://host:INVALID/path";')
        audit.source_index({'sources':self.sources})
    def test_correlations_do_not_claim_callsite_causality_and_exports_escape_markup(self):
        report=self.report();report['artifact']['name']='<script>alert(1)</script>'
        report['runtime_correlations']=audit.correlate(report,[{'flow_id':'flow','url':'https://api.example.test/runtime','status':200}])
        self.assertEqual(report['runtime_correlations'][0]['relationship'],'host_match_only')
        html,mime=reports.export(report,'html');self.assertNotIn(b'<script>',html);self.assertIn(b'&lt;script&gt;',html)
        pdf,_=reports.export(report,'pdf');self.assertTrue(pdf.startswith(b'%PDF'));self.assertGreater(len(pdf),1000)
        raw,_=reports.export(report,'json');self.assertEqual(json.loads(raw)['coverage']['confirmed_vulnerabilities'],0)
    def test_external_entities_are_rejected(self):
        (self.decoded/'AndroidManifest.xml').write_text('<!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/passwd">]><manifest>&x;</manifest>')
        with self.assertRaises(ValueError):self.report()


class EvidenceApiTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=lab_fixture.LabTests.asyncSetUp
    auth=lab_fixture.LabTests.auth
    call=lab_fixture.LabTests.call
    async def test_static_analysis_jobs_do_not_boot_android_and_timeline_is_scoped(self):
        # A genuinely missing project produces an error before any Android call.
        response=await self.call('android_project',{'operation':'audit','project':str(uuid.uuid4())})
        self.assertEqual(response.status_code,404);self.assertEqual(self.device.calls,[])
        timeline=await self.client.get('/v1/timeline',headers=self.auth());events=timeline.json()['events']
        self.assertEqual([x['kind'] for x in events],['action_started','action_failed'])
        other=await self.client.get('/v1/timeline',headers=self.auth(conversation=str(uuid.uuid4())))
        self.assertEqual(other.json()['events'],[])
    async def test_capture_eviction_is_explicit_and_persistent(self):
        state=self.app.state.lab
        for i in range(1010):state.capture('scope',{'url':str(i)})
        self.assertEqual(state.coverage('scope')['network_events_evicted'],10)
    async def test_batched_network_list_is_summary_and_selected_read_contains_the_body(self):
        scope=self.app.state.lab.scope({'sub':'owner','conversation':self.conversation})
        identifier=self.app.state.lab.capture(scope,{'phase':'request','flow_id':'probe','url':'https://test.invalid/probe','request_body':{'base64':'aGVsbG8=','available':True}})
        listed=await self.call('android_network',{'operation':'list','limit':50})
        self.assertNotIn('request_body',listed.json()['events'][0])
        full=await self.call('android_network',{'operation':'read','after':identifier-1})
        self.assertEqual(full.json()['events'][0]['id'],identifier)
        self.assertEqual(full.json()['events'][0]['request_body']['base64'],'aGVsbG8=')
    async def test_exports_require_owner_scope_and_no_running_device(self):
        scope=self.app.state.lab.scope({'sub':'owner','conversation':self.conversation})
        project=str(uuid.uuid4());root=self.app.state.lab.root/'projects'/scope/project;(root/'reports').mkdir(parents=True)
        (root/'project.json').write_text('{}');(root/'reports/original.json').write_text(json.dumps({'artifact':{'name':'test'},'inventory':{},'coverage':{},'findings':[]}))
        response=await self.client.get('/v1/projects/'+project+'/export?format=json',headers=self.auth())
        self.assertEqual(response.status_code,200,response.text);self.assertEqual(response.json()['timeline'],[])
        other=await self.client.get('/v1/projects/'+project+'/export',headers=self.auth(conversation=str(uuid.uuid4())))
        self.assertEqual(other.status_code,404);self.assertEqual(self.device.calls,[])

    async def test_agent_cannot_self_approve_modifications_and_consent_expires(self):
        scope=self.app.state.lab.scope({'sub':'owner','conversation':self.conversation});project=str(uuid.uuid4())
        root=self.app.state.lab.root/'projects'/scope/project;(root/'work/decoded').mkdir(parents=True)
        (root/'project.json').write_text('{}');file=root/'work/decoded/test.txt';file.write_text('original')
        args={'operation':'write','project':project,'path':'test.txt','content':'edited','expected_sha256':hashlib.sha256(b'original').hexdigest()}
        denied=await self.call('android_project',args,role='agent');self.assertEqual(denied.status_code,403);self.assertEqual(file.read_text(),'original')
        denied=await self.call('android_project',{'operation':'approve_changes','project':project},role='agent');self.assertEqual(denied.status_code,403)
        allowed=await self.call('android_project',{'operation':'approve_changes','project':project});self.assertEqual(allowed.status_code,200)
        response=await self.call('android_project',args,role='agent');self.assertEqual(response.status_code,200,response.text);self.assertEqual(file.read_text(),'edited')
        self.now+=601;denied=await self.call('android_project',args,role='agent');self.assertEqual(denied.status_code,403)

    async def test_trusted_session_grants_modifications_once_and_takeover_revokes_them(self):
        await lab_fixture.LabTests.start(self)
        scope=self.app.state.lab.scope({'sub':'owner','conversation':self.conversation});project=str(uuid.uuid4())
        root=self.app.state.lab.root/'projects'/scope/project;(root/'work/decoded').mkdir(parents=True)
        (root/'project.json').write_text('{}');file=root/'work/decoded/test.txt';file.write_text('original')
        args={'operation':'write','project':project,'path':'test.txt','content':'edited','expected_sha256':hashlib.sha256(b'original').hexdigest()}
        self.assertEqual((await self.call('android_device',{'operation':'trust'},role='agent')).status_code,400)
        self.assertEqual((await self.call('android_device',{'operation':'trust'})).status_code,200)
        response=await self.call('android_project',args,role='agent');self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(file.read_text(),'edited')
        await self.client.post('/v1/control/take',headers=self.auth())
        args.update(content='again',expected_sha256=hashlib.sha256(b'edited').hexdigest())
        self.assertEqual((await self.call('android_project',args,role='agent')).status_code,403)
        self.assertEqual(file.read_text(),'edited')

    async def test_takeover_interrupts_a_stalled_agent_action_without_waiting_for_tool_gate(self):
        await lab_fixture.LabTests.start(self);await self.call('android_device',{'operation':'release'})
        entered=asyncio.Event()
        async def stalled(*args):entered.set();await asyncio.Event().wait()
        self.device.action=stalled;identifier=str(uuid.uuid4())
        action=asyncio.create_task(self.call('android_ui',{'operation':'tap','x':.5,'y':.5},role='agent',identifier=identifier))
        await asyncio.wait_for(entered.wait(),1);started=time.monotonic()
        response=await self.client.post('/v1/control/take',headers=self.auth())
        self.assertEqual(response.status_code,200);self.assertLess(time.monotonic()-started,.5)
        interrupted=await asyncio.wait_for(action,1);self.assertEqual(interrupted.status_code,409)
        self.assertTrue(interrupted.json()['uncertain']);self.assertEqual(self.app.state.lab.load()['controller'],'human')
        again=await self.call('android_ui',{'operation':'tap','x':.5,'y':.5},role='agent',identifier=identifier)
        self.assertEqual(again.status_code,400)
