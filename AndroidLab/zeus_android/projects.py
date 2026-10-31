"""Bounded APK project storage. Originals are immutable; builds are separate jobs."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import uuid
import zipfile
from . import audit

MAX_APK = 256 * 1024 * 1024


class Projects:
    def __init__(self, root, on_event=None):
        self.root = Path(root); self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.tasks = set()
        self.on_event=on_event
        # A process killed during a build has an unknown/failed result, never a
        # success inferred from the mere presence of an output file.
        for file in self.root.glob("*/*/jobs/*.json"):
            value = json.loads(file.read_text())
            if value["status"] == "running": value.update(status="interrupted"); file.write_text(json.dumps(value))

    def project(self, scope, identifier):
        if not re.fullmatch(r"[a-f0-9]{64}", scope) or not re.fullmatch(r"[a-f0-9-]{36}", identifier): raise ValueError("Invalid project")
        path = self.root / scope / identifier
        if not (path / "project.json").is_file(): raise KeyError("Project not found")
        return path

    def list(self, scope):
        return [json.loads(p.read_text()) for p in (self.root / scope).glob("*/project.json")][:50]

    async def upload(self, scope, chunks, filename):
        if len(self.list(scope)) >= 10: raise ValueError("Remove a project before uploading another")
        total_disk = sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file())
        if total_disk > 2*1024**3: raise ValueError("Laboratory project quota reached")
        identifier = str(uuid.uuid4()); root = self.root / scope / identifier; root.mkdir(parents=True, mode=0o700)
        target = root / "original.apk"; digest, total = hashlib.sha256(), 0
        try:
            with target.open("xb") as file:
                async for block in chunks:
                    total += len(block)
                    if total > MAX_APK: raise ValueError("APK exceeds 256 MiB")
                    digest.update(block); file.write(block)
            with zipfile.ZipFile(target) as archive:
                entries = archive.infolist()
                if len(entries) > 20000 or sum(x.file_size for x in entries) > 512*1024**2 or "AndroidManifest.xml" not in archive.namelist(): raise ValueError("Invalid or oversized APK archive")
                for entry in entries:
                    if entry.filename.startswith('/') or '\\' in entry.filename or '..' in entry.filename.split('/') or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                        raise ValueError("APK contains unsafe archive entries")
                abis = sorted({n.filename.split('/')[1] for n in entries if n.filename.startswith('lib/') and len(n.filename.split('/')) > 2})
            os.chmod(target, 0o400)
            value = {"id": identifier, "name": Path(filename).name[:120], "bytes": total, "sha256": digest.hexdigest(), "abis": abis}
            (root / "project.json").write_text(json.dumps(value)); return value
        except BaseException:
            import shutil
            shutil.rmtree(root); raise

    @staticmethod
    def relative(root, name):
        if not isinstance(name, str) or not name or len(name) > 500 or "\\" in name or name.startswith("/") or any(p in {".", "..", ""} for p in name.split("/")): raise ValueError("Use a project-relative path")
        path = root / name
        for parent in [path, *path.parents]:
            if parent == root: break
            if parent.is_symlink(): raise ValueError("Project symlinks are not accessible")
        if root.resolve() not in path.resolve().parents: raise ValueError("Path escapes the project")
        return path

    async def operation(self, scope, operation, args, device):
        if operation == "list": return {"projects": self.list(scope)}
        root = self.project(scope, args.get("project", ""))
        variant=args.get('variant','original')
        if variant not in {'original','rebuilt'}:raise ValueError('Unknown APK variant')
        if operation=='report':
            report=self.report(root,variant);section=args.get('section','summary')
            if section=='summary':return {'artifact':report['artifact'],'inventory':{'package':report['inventory']['package'],'permission_count':len(report['inventory']['permissions']),'component_count':len(report['inventory']['components'])},'coverage':report['coverage'],'finding_count':len(report['findings']),'source_observation_count':len(report['source_observations']['matches'])}
            if section not in {'inventory','findings','dex','native_libraries','source_observations','coverage'}:raise ValueError('Unknown report section')
            value=report[section]
            if isinstance(value,list):value=value[max(0,int(args.get('offset',0))):max(0,int(args.get('offset',0)))+30]
            if section=='source_observations':value={**value,'matches':value['matches'][:30],'endpoints':value['endpoints'][:30]}
            return {section:value}
        if operation=='compare':
            original=self.report(root,'original');rebuilt=self.report(root,'rebuilt')
            left,right=original['inventory'],rebuilt['inventory']
            return {'original_sha256':original['artifact']['sha256'],'rebuilt_sha256':rebuilt['artifact']['sha256'],
                'original_preserved':hashlib.sha256((root/'original.apk').read_bytes()).hexdigest()==json.loads((root/'project.json').read_text())['sha256'],
                'inventory_changes':{key:{'original':left.get(key),'rebuilt':right.get(key)} for key in left if left.get(key)!=right.get(key)},
                'limitation':'Static comparison only; matching runtime behavior requires a separate recorded test.'}
        if operation=='search':
            evidence=root/'work/audit'/variant
            if not evidence.is_dir():evidence=root/'work'
            return await asyncio.to_thread(audit.source_index,{'sources':evidence/'sources','decoded':evidence/'decoded'},args.get('query'),80)
        if self.tasks and operation != "job": raise ValueError("Wait for the current APK job to finish")
        if operation == "install":
            name = "rebuilt.apk" if args.get("variant") == "rebuilt" else "original.apk"
            if not (root / name).is_file(): raise ValueError("The requested APK does not exist")
            replaced=False
            try:result = (await device.command("install", "-r", root / name, timeout=120)).decode(errors="replace")
            except ValueError as error:
                incompatible=any(marker in str(error) for marker in ('INSTALL_FAILED_UPDATE_INCOMPATIBLE','INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES'))
                if not incompatible:raise
                if name!='rebuilt.apk' or args.get('replace_existing') is not True:
                    raise ValueError('INSTALL_REQUIRES_REPLACEMENT: The installed app uses another signing key. Explicit replace_existing for the rebuilt test APK clears only that app\'s data in this emulator; original.apk is preserved.') from None
                manifest=root/'work/decoded/AndroidManifest.xml'
                if not manifest.is_file():raise ValueError('Decode the test APK identity before replacing an installation') from None
                package=audit.manifest_inventory(manifest)['package']
                if not isinstance(package,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+',package):raise ValueError('Decoded APK identity is invalid')
                removed=await device.command('uninstall',package,timeout=60)
                if b'Success' not in removed:raise ValueError('The old test installation could not be removed')
                try:result=(await device.command('install',root/name,timeout=120)).decode(errors='replace')
                except ValueError as failure:
                    try:rollback=await device.command('install',root/'original.apk',timeout=120);restored=b'Success' in rollback
                    except ValueError:restored=False
                    raise ValueError('Modified APK installation failed after replacement; original installation restored='+str(restored)+'. App data was reset. '+str(failure)[-500:]) from None
                replaced=True
            if "Success" not in result: raise ValueError("APK installation did not succeed: " + result[-500:])
            return {"installed": name,"replaced_existing":replaced,"device_app_data_reset":replaced}
        if operation == "job":
            identifier = str(args.get("job", ""))
            if not re.fullmatch(r"[a-f0-9-]{36}", identifier): raise ValueError("Invalid job id")
            return json.loads((root / "jobs" / (identifier + ".json")).read_text())
        if operation in {"files", "read", "write"}:
            decoded = root / "work" / ("sources" if args.get("tree") == "sources" else "decoded")
            if operation == "write" and args.get("tree") == "sources": raise ValueError("Decompiled Java is read-only; edit decoded resources/smali")
            if not decoded.is_dir(): raise ValueError("Decode this APK first")
            if operation == "files":
                files = [str(p.relative_to(decoded)) for p in decoded.rglob("*") if p.is_file() and not p.is_symlink()]
                return {"files": sorted(files)[:2000], "truncated": len(files) > 2000}
            file = self.relative(decoded, args.get("path", ""))
            if operation == "read":
                if file.stat().st_size > 100000: raise ValueError("File exceeds the text preview limit")
                content = file.read_bytes()
                return {"path": args["path"], "content": content.decode(), "sha256": hashlib.sha256(content).hexdigest()}
            content = args.get("content")
            if not isinstance(content, str) or len(content.encode()) > 100000: raise ValueError("Edit exceeds the text limit")
            old = file.read_bytes() if file.is_file() else b""
            if hashlib.sha256(old).hexdigest() != args.get("expected_sha256"): raise ValueError("File changed; read it again before editing")
            file.parent.mkdir(parents=True, exist_ok=True); file.write_text(content)
            return {"written": args["path"], "sha256": hashlib.sha256(content.encode()).hexdigest()}
        if operation not in {"analyze", "decode", "build", "audit"}: raise ValueError("Unknown project operation")
        if self.tasks: raise ValueError("Wait for the current APK job to finish")
        identifier = str(uuid.uuid4()); (root / "jobs").mkdir(exist_ok=True)
        state = {"id": identifier, "operation": operation, "variant":variant,"status": "running"}
        file = root / "jobs" / (identifier + ".json"); file.write_text(json.dumps(state))
        task = asyncio.create_task(self.run(root, state, file),name=scope+":"+identifier); self.tasks.add(task); task.add_done_callback(self.tasks.discard)
        return state

    async def run(self, root, state, file):
        try:
            build_uid = int(os.environ["ZEUS_ANDROID_BUILD_UID"]) if os.environ.get("ZEUS_ANDROID_BUILD_UID") else None
            if build_uid is not None:
                if os.geteuid() != 0: raise ValueError("APK tool isolation requires the configured unprivileged build user")
                for parent in [self.root.parent, self.root, root.parent]: os.chmod(parent, 0o711)
                os.chmod(root, 0o755); os.chmod(root / "original.apk", 0o444)
            work = root / "work"; work.mkdir(exist_ok=True)
            if build_uid is not None: os.chown(work, build_uid, build_uid)
            home=work/'.tool-home';home.mkdir(mode=0o700,exist_ok=True)
            if build_uid is not None:os.chown(home,build_uid,build_uid)
            operation = state["operation"]
            if operation == "analyze": commands = [["jadx", "--no-res", "--threads-count", "1", "-d", str(work / "sources"), str(root / "original.apk")]]
            elif operation == "decode": commands = [["apktool", "d", "-f", "-o", str(work / "decoded"), str(root / "original.apk")]]
            elif operation == 'audit':
                variant=state['variant'];target=root/('original.apk' if variant=='original' else 'rebuilt.apk')
                if not target.is_file():raise ValueError('Requested APK variant is missing')
                if build_uid is not None:os.chmod(target,0o444)
                evidence=work/'audit'/variant;evidence.mkdir(parents=True,exist_ok=True)
                if build_uid is not None:
                    for folder in (work/'audit',evidence):os.chown(folder,build_uid,build_uid)
                commands=[['apksigner','verify','--print-certs',str(target)],
                    ['apktool','d','-f','-o',str(evidence/'decoded'),str(target)],
                    ['jadx','--no-res','--threads-count','1','-d',str(evidence/'sources'),str(target)]]
            else:
                commands = [["apktool", "b", str(work / "decoded"), "-o", str(work / "unsigned.apk")],
                    ["zipalign", "-p", "-f", "4", str(work / "unsigned.apk"), str(work / "aligned.apk")],
                    ["apksigner", "sign", "--ks", os.environ.get("ZEUS_ANDROID_KEYSTORE", "/data/lab.keystore"), "--ks-pass", "pass:android", "--out", str(work / "rebuilt.apk"), str(work / "aligned.apk")],
                    ["apksigner", "verify", str(work / "rebuilt.apk")]]
            logs = []
            for command in commands:
                logs.append(await self.process(command,home=home))
            if operation=='audit':
                metadata=json.loads((root/'project.json').read_text());metadata['variant']=variant
                report=await asyncio.to_thread(audit.analyze,target,evidence/'decoded',evidence/'sources',metadata,logs[0])
                reports=root/'reports';reports.mkdir(exist_ok=True)
                temporary=reports/(variant+'.tmp');temporary.write_text(json.dumps(report,ensure_ascii=False));temporary.replace(reports/(variant+'.json'))
                state['report']={'variant':variant,'findings':len(report['findings']),'sha256':report['artifact']['sha256']}
            if operation == "build":
                import shutil
                source = self.relative(work, "rebuilt.apk")
                shutil.copyfile(source, root / "rebuilt.apk"); os.chmod(root / "rebuilt.apk", 0o400)
            state.update(status="completed", output="\n".join(logs)[-12000:])
        except asyncio.CancelledError: state.update(status="interrupted"); raise
        except Exception as error: state.update(status="failed", error=str(error)[-2000:])
        finally:
            file.write_text(json.dumps(state))
            if self.on_event:self.on_event(root.parent.name,'project_job_finished',{'actor':'worker','project':root.name,'job':state['id'],'operation':state['operation'],'status':state['status'],'error':state.get('error'),'report':state.get('report')})

    @staticmethod
    def report(root, variant='original'):
        if variant not in {'original','rebuilt'}:raise ValueError('Unknown APK variant')
        path=root/'reports'/(variant+'.json')
        if not path.is_file():raise ValueError('Run an audit for this APK variant first')
        return json.loads(path.read_text())

    @staticmethod
    async def process(command,home=None):
        # No broker/model credentials are inherited by decompilers/build tools.
        uid = int(os.environ["ZEUS_ANDROID_BUILD_UID"]) if os.environ.get("ZEUS_ANDROID_BUILD_UID") else None
        network_isolated=os.environ.get('ZEUS_ANDROID_TOOL_NETNS')=='1'
        if network_isolated:
            if uid is None or os.geteuid()!=0:raise ValueError('Tool network isolation requires a root launcher and configured build UID')
            command=['unshare','--net','--pid','--fork','--mount-proc','--setuid='+str(uid),'--setgid='+str(uid),'--',
                'prlimit','--as=4294967296','--nproc=128','--fsize=134217728','--cpu=600','--',*command]
        process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home or '/tmp'),
                 "XDG_CONFIG_HOME":str(Path(home or '/tmp')/'config'),"XDG_CACHE_HOME":str(Path(home or '/tmp')/'cache'),
                 "JAVA_TOOL_OPTIONS": "-Xmx1536m -XX:ActiveProcessorCount=2 -Duser.home="+str(home or '/tmp'), "LANG":"C.UTF-8"},
            cwd="/tmp", start_new_session=True, **({"extra_groups":[]} if network_isolated else {"user":uid,"group":uid,"extra_groups":[]} if uid is not None else {}))
        output = bytearray()
        try:
            async with asyncio.timeout(600):
                while block := await process.stdout.read(16384):
                    output.extend(block); del output[:-32000]
                if await process.wait(): raise ValueError(output.decode(errors="replace"))
            return output.decode(errors="replace")
        finally:
            if process.returncode is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                await process.wait()

    async def close(self):
        for task in list(self.tasks): task.cancel()
        await asyncio.gather(*list(self.tasks), return_exceptions=True)

    async def delete(self, scope):
        if not re.fullmatch(r"[a-f0-9]{64}",scope): raise ValueError("Invalid project scope")
        tasks=[task for task in self.tasks if task.get_name().startswith(scope+":")]
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        import shutil
        await asyncio.to_thread(shutil.rmtree,self.root/scope,True)
