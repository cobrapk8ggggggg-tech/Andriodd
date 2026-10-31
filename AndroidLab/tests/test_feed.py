"""Exercise actual HTTP streaming, not a buffering ASGI test transport."""
import asyncio
import json
import socket
import tempfile
import unittest
from unittest.mock import patch
import httpx
import uvicorn
from zeus_android.app import create_app
from zeus_android.tokens import encode
from test_lab import DeviceFixture, KEY, OWNER

class FeedTests(unittest.IsolatedAsyncioTestCase):
    async def test_first_event_arrives_before_response_completion_and_logs_survive_stop(self):
        with tempfile.TemporaryDirectory() as directory,patch.dict('os.environ',{'ZEUS_ANDROID_EXTERNAL_AVD':'1','ZEUS_ANDROID_CAPTURE_TOKEN':'c'*40}):
            app=create_app(directory,KEY,OWNER,DeviceFixture())
            listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();port=listener.getsockname()[1]
            server=uvicorn.Server(uvicorn.Config(app,log_level='error',access_log=False));serving=asyncio.create_task(server.serve(sockets=[listener]))
            try:
                for _ in range(100):
                    if server.started:break
                    await asyncio.sleep(.01)
                auth={'Authorization':'Bearer '+encode(KEY,OWNER,'conversation')}
                async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{port}',headers=auth,trust_env=False,timeout=3) as client:
                    async def call(name,operation,**extra):
                        response=await client.post('/v1/tool',json={'name':name,'arguments':{'operation':operation,**extra},'request_id':str(__import__('uuid').uuid4())})
                        self.assertEqual(response.status_code,200,response.text);return response.json()
                    await call('android_device','start');await call('android_network','start')
                    async with client.stream('GET','/v1/network/feed') as response:
                        self.assertEqual(response.status_code,200);self.assertIn('no-transform',response.headers['cache-control'])
                        event={'started':app.state.lab.load()['started'],'phase':'request','flow_id':'live','sequence':1,'url':'https://test.invalid/chat','request_body':{'base64':'cHJpdmF0ZQ=='}}
                        sent=await client.post('/internal/capture',headers={'X-Capture-Token':'c'*40},json=event);self.assertTrue(sent.json()['accepted'])
                        async def first():
                            async for line in response.aiter_lines():
                                if line.startswith('data: '):return json.loads(line[6:])
                        value=await asyncio.wait_for(first(),1)
                        self.assertEqual(value['phase'],'request');self.assertNotIn('request_body',value)
                    await call('android_device','stop')
                    details=await call('android_network','read',after=0)
                    self.assertEqual(details['events'][0]['request_body']['base64'],event['request_body']['base64'])
                    self.assertEqual(details['events'][0]['request_body']['text_preview'],'private')
                    other=await client.get('/v1/network/feed',headers={'Authorization':'Bearer '+encode(KEY,OWNER,'other')})
                    self.assertEqual(other.text,'')
                    denied=await client.get('/v1/network/feed',headers={'Authorization':'Bearer '+encode(KEY,OWNER,'conversation','agent')})
                    self.assertEqual(denied.status_code,403)
            finally:
                server.should_exit=True;await asyncio.wait_for(serving,5)
