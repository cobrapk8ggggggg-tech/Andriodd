import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from zeus_android.projects import Projects
from zeus_android.diagnostics import Diagnostics


class DiagnosticTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_subprocess_log_recording_is_bounded_saved_and_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            projects=Projects(directory);scope='a'*64;project='11111111-1111-4111-8111-111111111111'
            root=projects.root/scope/project;root.mkdir(parents=True);(root/'project.json').write_text('{}')
            class Source:
                def argv(self,*args):return [sys.executable,'-u','-c','import time;print("actual process log",flush=True);time.sleep(120)']
            events=[];diagnostics=Diagnostics(projects,Source(),lambda *v:events.append(v));self.addAsyncCleanup(diagnostics.close)
            value=await diagnostics.start(scope,{'project':project,'kind':'logcat'})
            for _ in range(100):
                if (root/'evidence'/value['file']).exists() and (root/'evidence'/value['file']).stat().st_size:break
                await asyncio.sleep(.01)
            await diagnostics.stop(scope)
            path,record=diagnostics.artifact(scope,project,value['id'])
            self.assertEqual(record['status'],'stopped');self.assertIn('actual process log',path.read_text())
            self.assertEqual(diagnostics.processes,{});self.assertTrue(events)
            with self.assertRaises(ValueError):diagnostics.artifact(scope,project,'../../outside')
            with self.assertRaises(KeyError):diagnostics.artifact('b'*64,project,value['id'])

    async def test_arbitrary_text_is_not_labeled_as_a_valid_pcap(self):
        with tempfile.TemporaryDirectory() as directory:
            projects=Projects(directory);scope='a'*64;project='11111111-1111-4111-8111-111111111111'
            root=projects.root/scope/project;root.mkdir(parents=True);(root/'project.json').write_text('{}')
            class Source:
                async def command(self,*a,**kw):return b'/system/bin/tcpdump'
                def argv(self,*args):return [sys.executable,'-c','print("permission denied")']
            diagnostics=Diagnostics(projects,Source(),lambda *v:None);self.addAsyncCleanup(diagnostics.close)
            value=await diagnostics.start(scope,{'project':project,'kind':'pcap'})
            await asyncio.gather(*list(diagnostics.tasks.values()))
            _,record=diagnostics.artifact(scope,project,value['id']);self.assertEqual(record['status'],'failed')
            self.assertIn('not a PCAP',record['error'])
