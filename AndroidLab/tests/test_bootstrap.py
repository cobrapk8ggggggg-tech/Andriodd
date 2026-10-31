import json
import tempfile
import unittest
import uuid
import httpx
from zeus_android.app import create_app
from zeus_android.tokens import decode,encode

class BootstrapTests(unittest.IsolatedAsyncioTestCase):
    async def test_role_renewal_never_shares_signing_key_and_cannot_outlive_session(self):
        with tempfile.TemporaryDirectory() as root:
            now=[10000];key='private-test-signing-key-00000000000000000';conversation=str(uuid.uuid4())
            access={'conversation':conversation,'viewer':'viewer-opaque-'+'a'*40,'agent':'agent-opaque-'+'b'*40,'expires':10400,'url':'https://temporary-test.trycloudflare.com'}
            app=create_app(root=root,key=key,owner='owner',clock=lambda:now[0],bootstrap=access)
            try:
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://test') as client:
                    denied=await client.post('/v1/access/renew',headers={'Authorization':'Bearer wrong'});self.assertEqual(denied.status_code,401)
                    for role in ('viewer','agent'):
                        response=await client.post('/v1/access/renew',headers={'Authorization':'Bearer '+access[role]})
                        self.assertEqual(response.status_code,200);value=response.json()
                        self.assertEqual(decode(key,value['token'],now=now[0])['role'],role);self.assertEqual(value['expires_in'],300)
                        self.assertNotIn(key,json.dumps(value));self.assertNotIn(access['viewer'],json.dumps(value));self.assertNotIn(access['agent'],json.dumps(value))
                    foreign=encode(key,'owner',str(uuid.uuid4()),now=now[0])
                    self.assertEqual((await client.get('/v1/session',headers={'Authorization':'Bearer '+foreign})).status_code,401)
                    now[0]=10300
                    response=await client.post('/v1/access/renew',headers={'Authorization':'Bearer '+access['viewer']})
                    self.assertEqual(response.json()['expires_in'],100)
                    now[0]=10401
                    self.assertEqual((await client.post('/v1/access/renew',headers={'Authorization':'Bearer '+access['viewer']})).status_code,401)
            finally:app.state.lab.close()
