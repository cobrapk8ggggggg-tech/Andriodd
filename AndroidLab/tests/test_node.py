import asyncio
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer
import httpx

spec=importlib.util.spec_from_file_location('lab_node',Path(__file__).parents[1]/'node_controller.py')
node=importlib.util.module_from_spec(spec);spec.loader.exec_module(node)


class NodeTests(unittest.IsolatedAsyncioTestCase):
    async def test_host_stops_an_overdue_device_without_a_working_worker(self):
        commands=[]
        def run(command,**kwargs):
            commands.append(command)
            return SimpleNamespace(returncode=0,stdout=b'{"Running":true,"StartedAt":"2026-01-01T00:00:00Z"}')
        with patch.object(node.subprocess,'run',side_effect=run),patch.object(node.time,'time',return_value=1767227500):
            node.enforce_deadline()
        self.assertEqual(commands[-1],['docker','stop','--time','5','zeus-lab-android'])

    async def test_only_fixed_container_operations_are_authenticated_and_reset_can_retry(self):
        commands=[]
        def run(command,**kwargs):
            commands.append(command)
            return SimpleNamespace(returncode=1 if 'inspect' in command else 0)
        server=ThreadingHTTPServer(('127.0.0.1',0),node.Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with patch.dict(os.environ,{'ZEUS_ANDROID_NODE_TOKEN':'n'*40}),patch.object(node.subprocess,'run',side_effect=run):
                async with httpx.AsyncClient(base_url='http://127.0.0.1:'+str(server.server_address[1]),trust_env=False) as client:
                    self.assertEqual((await client.post('/start')).status_code,403);self.assertFalse(commands)
                    headers={'Authorization':'Bearer '+'n'*40}
                    self.assertEqual((await client.post('/arbitrary',headers=headers)).status_code,404);self.assertFalse(commands)
                    self.assertEqual((await client.post('/start',headers=headers,json={'container':'another-service'})).status_code,200)
                    self.assertEqual(commands[0],['docker','start','zeus-lab-android'])
                    for _ in range(2):self.assertEqual((await client.post('/reset',headers=headers)).status_code,200)
                    self.assertFalse(any(c[:3]==['docker','rm','-f'] for c in commands))
        finally:
            await asyncio.to_thread(server.shutdown);server.server_close();thread.join(timeout=2)
