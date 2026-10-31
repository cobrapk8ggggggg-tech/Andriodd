"""Bounded genuine device evidence; no synthetic logs or fallback recordings."""
import asyncio
import json
import os
from pathlib import Path
import re
import signal
import time
import uuid


class Diagnostics:
    def __init__(self, projects, device, record):
        self.projects,self.device,self.record=projects,device,record
        self.tasks={};self.processes={}
        for file in projects.root.glob('*/*/evidence/*.json'):
            try:value=json.loads(file.read_text())
            except ValueError:continue
            if value.get('status')=='running':value.update(status='interrupted');file.write_text(json.dumps(value))

    async def capabilities(self):
        result={'logcat':True,'screenrecord':False,'pcap':False,'frida_configured':bool(os.environ.get('ZEUS_ANDROID_FRIDA_ENDPOINT')),'mobsf_configured':bool(os.environ.get('ZEUS_ANDROID_MOBSF_URL'))}
        for field,name in [('screenrecord','screenrecord'),('pcap','tcpdump')]:
            try:result[field]=bool((await self.device.command('shell','command','-v',name,timeout=5)).strip())
            except (ValueError,OSError,asyncio.TimeoutError):result[field]=False
        return result

    @staticmethod
    def package(value):
        if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+',value):raise ValueError('Use an installed Android package name')
        return value

    async def logs(self, args):
        argv=['logcat','-d','-t','150','-v','epoch']
        if args.get('package'):
            package=self.package(args['package'])
            raw=(await self.device.command('shell','pidof',package)).decode().strip().split()
            if not raw or not raw[0].isdigit():raise ValueError('Application is not running')
            argv+=['--pid='+raw[0]]
        data=await self.device.command(*argv,timeout=10,limit=1_000_000)
        return {'logcat':data[-24000:].decode(errors='replace'),'truncated':len(data)>24000,'source':'actual_device_logcat','scope':'selected_pid' if args.get('package') else 'device'}

    def records(self, scope, project):
        root=self.projects.project(scope,project)
        return {'records':[json.loads(p.read_text()) for p in sorted((root/'evidence').glob('*.json'))][-100:]}

    def artifact(self, scope, project, identifier):
        root=self.projects.project(scope,project)
        try:uuid.UUID(identifier)
        except (ValueError,TypeError):raise ValueError('Invalid recording id') from None
        meta=root/'evidence'/(identifier+'.json')
        if not meta.is_file():raise KeyError('Recording is missing')
        value=json.loads(meta.read_text());path=root/'evidence'/value['file']
        if value['status']=='running':raise ValueError('Stop the recording before downloading')
        if not path.is_file() or path.is_symlink():raise KeyError('Recording file is missing')
        return path,value

    async def start(self, scope, args):
        kind=args.get('kind');project=args.get('project');root=self.projects.project(scope,project)
        if kind not in {'logcat','pcap','video'}:raise ValueError('Recording kind must be logcat, pcap or video')
        if any(key.startswith(scope+':') for key in self.tasks):raise ValueError('Stop the current evidence recording first')
        commands={'logcat':['logcat','-v','epoch'],
            'pcap':['exec-out','tcpdump','-U','-i','any','-s','256','-w','-'],
            'video':['exec-out','screenrecord','--time-limit','180','--bit-rate','1500000','--output-format=h264','-']}
        if kind in {'pcap','video'}:
            supported=await self.capabilities()
            if not supported['pcap' if kind=='pcap' else 'screenrecord']:raise ValueError('The device does not provide '+('tcpdump; PCAP is unavailable' if kind=='pcap' else 'screenrecord'))
        directory=root/'evidence';directory.mkdir(exist_ok=True,mode=0o700)
        identifier=str(uuid.uuid4());extension={'logcat':'log','pcap':'pcap','video':'h264'}[kind]
        value={'id':identifier,'kind':kind,'project':project,'status':'running','started':time.time(),'file':identifier+'.'+extension,'bytes':0,
            'limits':{'max_bytes':32*1024*1024,'max_seconds':180,'pcap_snaplen':256 if kind=='pcap' else None}}
        meta=directory/(identifier+'.json');meta.write_text(json.dumps(value))
        key=scope+':'+identifier
        task=asyncio.create_task(self.run(key,directory,meta,value,commands[kind]));self.tasks[key]=task
        task.add_done_callback(lambda _:self.tasks.pop(key,None));return value

    async def run(self,key,directory,meta,value,argv):
        process=None;error_tail=bytearray();limit=value['limits']['max_bytes']
        try:
            env={k:os.environ[k] for k in ('PATH','HOME','LANG') if k in os.environ}
            process=await asyncio.create_subprocess_exec(*self.device.argv(*argv),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env=env,start_new_session=True)
            self.processes[key]=process
            async def errors():
                while chunk:=await process.stderr.read(4096):error_tail.extend(chunk);del error_tail[:-4000]
            reader=asyncio.create_task(errors())
            try:
                async with asyncio.timeout(180):
                    with (directory/value['file']).open('xb') as file:
                        while chunk:=await process.stdout.read(65536):
                            if value['bytes']+len(chunk)>limit:value['status']='size_limit';break
                            file.write(chunk);value['bytes']+=len(chunk)
                    if value['status']=='running':
                        code=await process.wait();value['status']='completed' if code==0 and value['bytes'] else 'failed'
            except asyncio.TimeoutError:value['status']='time_limit'
            finally:
                if process.returncode is None:
                    try:os.killpg(process.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    try:await asyncio.wait_for(process.wait(),3)
                    except asyncio.TimeoutError:os.killpg(process.pid,signal.SIGKILL);await process.wait()
                await reader
            if value['kind']=='pcap' and value['bytes']:
                with (directory/value['file']).open('rb') as file:magic=file.read(4)
                if magic not in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d',b'\x0a\x0d\x0d\x0a'):
                    value.update(status='failed',error='Device output is not a PCAP stream')
        except asyncio.CancelledError:
            value['status']='stopped'
            if process and process.returncode is None:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                await process.wait()
        except Exception as error:value.update(status='failed',error=str(error)[:1000])
        finally:
            self.processes.pop(key,None);value['ended']=time.time()
            if error_tail:value['device_stderr']=error_tail.decode(errors='replace')
            if value['status']=='stopped' and not value['bytes']:value['status']='interrupted_empty'
            meta.write_text(json.dumps(value));self.record(key.split(':')[0],'recording_finished',value)

    async def stop(self, scope):
        selected=[task for key,task in self.tasks.items() if key.startswith(scope+':')]
        for task in selected:task.cancel()
        await asyncio.gather(*selected,return_exceptions=True)
        return {'stopped_recordings':len(selected)}

    async def close(self):
        for task in list(self.tasks.values()):task.cancel()
        await asyncio.gather(*list(self.tasks.values()),return_exceptions=True)
