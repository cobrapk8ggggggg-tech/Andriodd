import asyncio
import json
from pathlib import Path
import time
import unittest
import uuid
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from zeus_android.mailbox import EmergencyMailbox
from zeus_android.sealed import seal,b64
import test_lab as fixture


class EmergencyTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=fixture.LabTests.asyncSetUp
    auth=fixture.LabTests.auth
    call=fixture.LabTests.call

    def mailbox(self):
        private=X25519PrivateKey.generate();session=str(uuid.uuid4())
        key=private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        public=b64(private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
        path=Path(self.temp.name)/'emergency.json';published=[];errors=[]
        value=EmergencyMailbox(path,session,key,'viewer-bootstrap',lambda:self.auth()['Authorization'][7:],self.client,
                               lambda n,v:published.append(v),errors.append)
        def write(credential='viewer-bootstrap',box_session=None):
            command={'name':'__take','credential':credential,'request_id':str(uuid.uuid4())}
            path.write_text(json.dumps({'session':session,'payload':seal(json.dumps(command).encode(),public,box_session or session)}))
        return value,write,published,errors

    async def test_takeover_bypasses_a_stalled_ordinary_command_and_revokes_trust(self):
        await fixture.LabTests.start(self);await self.call('android_device',{'operation':'trust'})
        entered=asyncio.Event()
        async def stalled(*args):entered.set();await asyncio.Event().wait()
        self.device.action=stalled
        active=asyncio.create_task(self.call('android_ui',{'operation':'tap','x':.5,'y':.5},role='agent'))
        await asyncio.wait_for(entered.wait(),1)
        mailbox,write,published,_=self.mailbox();write()
        await asyncio.wait_for(mailbox.check(),1)
        self.assertEqual(published[0]['http_status'],200)
        response=await asyncio.wait_for(active,1);self.assertEqual(response.status_code,409)
        self.assertEqual(self.app.state.lab.load()['controller'],'human')
        self.assertFalse(self.app.state.lab.load()['trusted'])
        await mailbox.check();self.assertEqual(len(published),1)

    async def test_agent_cannot_use_the_viewer_emergency_channel(self):
        await fixture.LabTests.start(self);await self.call('android_device',{'operation':'release'})
        mailbox,write,published,_=self.mailbox();write('agent-bootstrap')
        with self.assertRaisesRegex(ValueError,'viewer'):await mailbox.check()
        self.assertEqual(self.app.state.lab.load()['controller'],'agent');self.assertEqual(published,[])

    async def test_invalid_ciphertext_does_not_disable_subsequent_takeover(self):
        await fixture.LabTests.start(self)
        mailbox,write,published,errors=self.mailbox();stop=asyncio.Event()
        mailbox.path.write_text(json.dumps({'session':mailbox.session,'payload':{'version':1,'session':mailbox.session,'ephemeral_public_key':b64(b'1'*32),'nonce':b64(b'0'*12),'ciphertext':b64(b'0'*16)}}))
        task=asyncio.create_task(mailbox.run(stop,time.time()+4))
        try:
            await asyncio.sleep(.05);self.assertTrue(errors)
            write()
            for _ in range(30):
                if published:break
                await asyncio.sleep(.05)
            self.assertEqual(published[0]['http_status'],200)
        finally:stop.set();await task
