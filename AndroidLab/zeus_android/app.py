"""Runs only on the separate Android node. No Docker socket is mounted here."""
import asyncio
import base64
from contextlib import asynccontextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
import zlib
from uuid import UUID
from urllib.parse import unquote
from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from .tokens import decode, encode
from .device import Device
from .state import State
from .projects import Projects
from .video import Video
from .lifecycle import Lifecycle
from .ice import servers as ice_servers
from . import audit, reports
from .diagnostics import Diagnostics
from .streaming import SocketVideo


class Call(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    name: str = Field(pattern="^android_(device|ui|screenshot|network|project)$")
    arguments: dict = Field(default_factory=dict)
    request_id: str = Field(min_length=1, max_length=180, pattern=r"^[a-zA-Z0-9_.:-]+$")


def create_app(root=None, key=None, owner=None, device=None, clock=time.time, bootstrap=None):
    signing_key = key or os.environ.get("ZEUS_ANDROID_SIGNING_KEY", "")
    allowed_owner = owner or os.environ.get("ZEUS_ANDROID_OWNER_ID", "")
    if len(signing_key) < 32 or not allowed_owner: raise ValueError("Configure an owner and a laboratory signing key")
    state = State(root or os.environ.get("ZEUS_ANDROID_DATA", "/data"), clock)
    projects = Projects(state.root / "projects",on_event=lambda scope,kind,details:record(scope,kind,details))
    device = device or Device(os.environ.get("ZEUS_ANDROID_ADB", "android:5555"))
    video = Video(device); gate = asyncio.Lock(); lifecycle = Lifecycle(); observers = set()
    active_agent={}
    socket_video=SocketVideo(device);sockets=set()

    def notify():
        for observer in observers: observer.set()

    def record(scope,kind,details):
        identifier=state.record(scope,kind,details);notify();return identifier

    diagnostics=Diagnostics(projects,device,record)

    def summary(event):
        return {k:v for k,v in event.items() if k in {'id', 'flow_id', 'sequence', 'phase', 'started', 'observed', 'method', 'url', 'status', 'direction', 'message_type', 'error','sni','duration_ms','interpretation','observer_dropped_total','observer_delivery_failures_total'}}

    def network(scope, operation, args, role):
        events = state.events(scope, max(0, int(args.get('after', 0))), 1 if operation == 'read' else min(50,max(1,int(args.get('limit',5)))))
        if operation == 'list': events = [summary(event) for event in events]
        else:
            for event in events:
                for field,header in [('request_body','request_headers'),('response_body','response_headers')]:
                    part=event.get(field)
                    if not part or not part.get('base64'):continue
                    try:
                        raw=base64.b64decode(part['base64'],validate=True)
                        encoding=next((v for k,v in event.get(header,{}).items() if k.lower()=='content-encoding'),'')
                        if encoding=='gzip':raw=zlib.decompressobj(16+zlib.MAX_WBITS).decompress(raw,32768)
                        elif encoding=='deflate':raw=zlib.decompressobj().decompress(raw,32768)
                        elif encoding not in ('','identity'):part['preview_unavailable']='Unsupported content encoding';continue
                        part['text_preview']=raw[:(2048 if role=='agent' else 32768)].decode('utf-8',errors='replace')
                        part['preview_limit_bytes']=2048 if role=='agent' else 32768
                    except (ValueError,zlib.error):part['preview_unavailable']='Incomplete or invalid encoded body'
        if operation!='list' and role == 'agent':
            # Keep structured model results below the cloud tool output limit.
            for event in events:
                for field in ('request_body', 'response_body'):
                    if field in event and len(event[field].get('base64', '')) > 4096:
                        event[field] = {**event[field], 'base64':event[field]['base64'][:4096], 'truncated':True}
                for field in ('request_headers', 'response_headers'):
                    if field in event: event[field] = dict(list(event[field].items())[:12])
        return {'events':events}
    initial = state.load()
    if initial and initial["status"] == "running": initial.update(status="interrupted", capture=False); state.save(initial)

    async def stop(value, reason):
        await diagnostics.stop(value['scope'])
        await socket_video.close()
        await video.close()
        try:
            await device.command("shell", "settings", "put", "global", "http_proxy", ":0")
            await device.command("shell", "input", "keyevent", "223")
        except (ValueError, OSError, asyncio.TimeoutError): pass
        try: await lifecycle.action("stop")
        except ValueError:
            value.update(status="stop_failed", capture=False, reason="تعذر تأكيد إيقاف Android؛ أعد محاولة الإيقاف."); state.save(value); raise
        value.update(status="stopped", capture=False, reason=reason); state.save(value); notify()

    async def sweep():
        while True:
            await asyncio.sleep(10)
            async with gate:
                value = state.load()
                if value and value["status"] == "running" and (clock() >= value["deadline"] or clock()-value["activity"] >= 300 and not projects.tasks):
                    try: await stop(value, "time_limit" if clock() >= value["deadline"] else "idle")
                    except ValueError: pass
                elif value and value["status"] == "stop_failed":
                    try: await stop(value, "retry_stop")
                    except ValueError: pass

    @asynccontextmanager
    async def lifespan(app):
        interrupted=state.load()
        if interrupted and interrupted["status"]=="interrupted":
            try: await stop(interrupted,"worker_restart")
            except ValueError: pass  # stop_failed is retried by the independent sweep.
        worker = asyncio.create_task(sweep())
        try: yield
        finally:
            worker.cancel(); await asyncio.gather(worker, return_exceptions=True)
            await diagnostics.close();await projects.close();await socket_video.close(); await video.close(); state.close()

    app = FastAPI(title="ZEUS Android Laboratory", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.lab, app.state.device, app.state.projects = state, device, projects

    @app.middleware("http")
    async def headers(request, call_next):
        # APK uploads are streamed and bounded in Projects; JSON is much smaller.
        limit = 256*1024**2 if request.url.path == "/v1/upload" else 200000
        try: length = int(request.headers.get("content-length", "0"))
        except ValueError: return JSONResponse({"detail":"Invalid length"}, 400)
        if length > limit: return JSONResponse({"detail":"Request too large"}, 413)
        if request.method == "POST" and request.url.path != "/v1/upload":
            chunks, total = [], 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > limit: return JSONResponse({"detail":"Request too large"}, 413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        response = await call_next(request)
        cache = response.headers.get('Cache-Control', 'no-store')
        response.headers.update({"Cache-Control":cache, "Referrer-Policy":"no-referrer", "X-Content-Type-Options":"nosniff",
            "Content-Security-Policy":"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; media-src 'self' blob:; img-src 'self' blob: data:; frame-ancestors 'none'; base-uri 'none'"})
        return response

    async def claims(authorization: str = Header(default="")):
        try: value = decode(signing_key, authorization.removeprefix("Bearer "), clock())
        except ValueError: raise HTTPException(401, "انتهت صلاحية المختبر؛ أغلقه وافتحه مجددًا.") from None
        if value["sub"] != allowed_owner: raise HTTPException(403, "Laboratory belongs to another account")
        if bootstrap and (value['conversation']!=bootstrap['conversation'] or clock()>=bootstrap['expires']):raise HTTPException(401,'Temporary laboratory session ended')
        return value

    @app.post('/v1/access/renew')
    async def renew(authorization:str=Header(default='')):
        if not bootstrap or clock()>=bootstrap['expires']:raise HTTPException(401,'Temporary session ended')
        secret=authorization.removeprefix('Bearer ');role=None
        if len(secret)<=200:
            for candidate in ('viewer','agent'):
                if hmac.compare_digest(secret,bootstrap[candidate]):role=candidate
        if role is None:raise HTTPException(401,'Invalid temporary session access')
        lifetime=min(300,int(bootstrap['expires']-clock()))
        return {'url':bootstrap['url']+'/lab/','token':encode(signing_key,allowed_owner,bootstrap['conversation'],role,ttl=lifetime,now=clock()),
            'owner':allowed_owner,'conversation':bootstrap['conversation'],'role':role,'expires_in':lifetime,'session_deadline':bootstrap['expires']}

    @app.exception_handler(ValueError)
    async def invalid(_, error): return JSONResponse({"detail":str(error)[:1000]}, 400)
    @app.exception_handler(KeyError)
    async def missing(_, error): return JSONResponse({"detail":"العنصر غير موجود في هذه المحادثة."}, 404)
    @app.exception_handler(RequestValidationError)
    async def bad_input(_, error): return JSONResponse({"detail":"قيم الطلب غير صالحة."}, 422)

    @app.get("/health")
    async def health(): return {"service":"zeus-android", "billing_note":"Stopping a session does not stop the host VM"}

    @app.get("/lab/")
    async def page(): return FileResponse(Path(__file__).parent / "web/index.html")
    @app.get("/lab/{name}")
    async def asset(name: str):
        if name not in {"lab.js", "lab.css", "transports.js"}: raise HTTPException(404)
        return FileResponse(Path(__file__).parent / "web" / name)

    @app.get("/v1/session")
    async def session(value=Depends(claims)):
        saved = state.load()
        if not saved or saved["scope"] != state.scope(value): return {"status":"stopped", "controller":"human", "capture":False}
        return {k:v for k,v in saved.items() if k not in {"scope", "owner"}}

    @app.get('/v1/transport')
    async def transport(value=Depends(claims)):
        return {'preferred':'websocket' if os.environ.get('ZEUS_ANDROID_TUNNEL')=='1' else 'webrtc',
            'modes':['fmp4','frames'],'frames_are_video':False,'network_feed':'websocket' if os.environ.get('ZEUS_ANDROID_TUNNEL')=='1' else 'sse'}

    @app.websocket('/v1/stream')
    async def stream(socket:WebSocket):
        if len(sockets)>=6:await socket.close(code=1013);return
        sockets.add(socket);observer=None;watcher=None
        try:
            await socket.accept()
            first=await asyncio.wait_for(socket.receive_text(),5)
            if len(first)>8000:await socket.close(code=1009);return
            message=json.loads(first)
            if not isinstance(message,dict):raise ValueError('Invalid stream authentication')
            value=await claims('Bearer '+str(message.get('token','')))
            if value['role']!='viewer':await socket.close(code=1008);return
            owner_task=asyncio.current_task()
            async def watch_disconnect():
                while True:
                    incoming=await socket.receive()
                    if incoming['type']=='websocket.disconnect':owner_task.cancel();return
                    # There are no command frames on this read-only connection.
                    await socket.close(code=1008);owner_task.cancel();return
            watcher=asyncio.create_task(watch_disconnect())
            channel=message.get('channel');scope=state.scope(value)
            if channel in ('video','frames'):
                state.owned(value)
                if channel=='video':
                    generator=socket_video.fragments()
                    try:
                        async for fragment in generator:
                            if clock()>=value['exp']:break
                            current=state.load()
                            if not current or current['scope']!=scope or current['status']!='running':break
                            if isinstance(fragment,bytes):await asyncio.wait_for(socket.send_bytes(fragment),5)
                            else:await socket.send_json(fragment)
                    finally:await generator.aclose()
                else:
                    await socket.send_json({'mode':'frames','interval_seconds':1,'notice':'Successive screenshots, not live video'})
                    while clock()<value['exp']:
                        state.owned(value);await asyncio.wait_for(socket.send_bytes(await device.screenshot()),5);await asyncio.sleep(1)
            elif channel in ('network','timeline'):
                cursor=max(0,int(message.get('after',0)));observer=asyncio.Event();observers.add(observer)
                while clock()<value['exp']:
                    observer.clear();batch=state.events(scope,cursor) if channel=='network' else state.history(scope,cursor)
                    if batch:
                        for event in batch:
                            cursor=event['id'];await socket.send_json({'channel':channel,'event':summary(event) if channel=='network' else event})
                        continue
                    try:await asyncio.wait_for(observer.wait(),15)
                    except asyncio.TimeoutError:await socket.send_json({'heartbeat':True})
            else:await socket.close(code=1008);return
        except (ValueError,KeyError,TypeError,HTTPException,asyncio.TimeoutError,asyncio.CancelledError,WebSocketDisconnect,RuntimeError):pass
        finally:
            if watcher:
                watcher.cancel();await asyncio.gather(watcher,return_exceptions=True)
            if observer:observers.discard(observer)
            sockets.discard(socket)
            try:await socket.close()
            except (RuntimeError,WebSocketDisconnect):pass

    @app.get('/v1/network/feed')
    async def network_feed(request: Request, after: int = 0, value=Depends(claims)):
        if value['role'] != 'viewer': raise HTTPException(403)
        if len(observers) >= 4: raise HTTPException(429, 'Too many laboratory viewers')
        observer = asyncio.Event(); observers.add(observer)
        async def events():
            cursor = max(0, after); scope = state.scope(value)
            try:
                while clock() < value['exp']:
                    observer.clear()
                    batch = state.events(scope, cursor)
                    if batch:
                        for event in batch:
                            cursor = event['id']
                            yield 'id: '+str(cursor)+'\ndata: '+json.dumps(summary(event), ensure_ascii=False)+'\n\n'
                        continue
                    saved = state.load()
                    if not saved or saved['scope'] != scope or saved['status'] != 'running' or not saved['capture']: break
                    try: await asyncio.wait_for(observer.wait(), min(15, max(.01, value['exp']-clock())))
                    except asyncio.TimeoutError: yield ': heartbeat\n\n'
                    if await request.is_disconnected(): break
            finally: observers.discard(observer)
        return StreamingResponse(events(), media_type='text/event-stream', headers={'X-Accel-Buffering':'no', 'Cache-Control':'no-store, no-transform'})

    async def execute_tool(call: Call, value):
        async with gate:
            args = call.arguments; operation = args.get("operation", "status"); scope = state.scope(value)
            if len(json.dumps(args)) > 120000: raise ValueError("Arguments too large")
            read_only = call.name == "android_screenshot" or call.name == "android_device" and operation in {"status","timeline","capabilities","logs","records"} or call.name == "android_ui" and operation == "tree" or call.name == "android_network" and operation in {"list", "read","coverage"} or call.name == "android_project" and operation in {"list", "job", "files", "read","report","search","compare"}
            digest = hashlib.sha256(json.dumps([call.name, args], sort_keys=True).encode()).hexdigest()
            if not read_only:
                prior = state.db.execute("SELECT digest,value FROM operations WHERE scope=? AND id=?", (scope, call.request_id)).fetchone()
                if prior:
                    if prior[0] != digest: raise ValueError("An operation id cannot be reused with different arguments")
                    result = json.loads(prior[1])
                    if result.get("uncertain"): raise ValueError("Previous action was interrupted; inspect the device before retrying with a new id")
                    return result
            saved = state.load()
            if call.name == "android_device" and operation == "status": return await session(value)
            if call.name=='android_project' and operation=='approve_changes':
                if value['role']!='viewer':raise HTTPException(403,'Only the user can approve test APK modifications')
                project=args.get('project','');projects.project(scope,project)
                consent=state.consent(scope,project,'modify',{'operations':['write','build','install_rebuilt']})
                state.record(scope,'modification_approved',{'actor':'viewer','project':project,'expires':consent['expires']})
                result={'approved':True,'expires':consent['expires'],'project':project}
                state.db.execute('INSERT INTO operations VALUES(?,?,?,?)',(scope,call.request_id,digest,json.dumps(result)));state.db.commit()
                return result
            sensitive=call.name=='android_project' and (operation in {'write','build'} or operation=='install' and args.get('variant')=='rebuilt')
            if sensitive and value['role']=='agent' and not (saved and saved.get('scope')==scope and saved.get('trusted') and saved.get('controller')=='agent') and not state.consent(scope,args.get('project',''),'modify'):
                raise HTTPException(403,'تحتاج نسخة الاختبار موافقة صريحة لهذا المشروع؛ اطلب موافقة المستخدم أولًا.')
            if call.name=='android_device' and operation=='timeline':return {'events':state.history(scope,int(args.get('after',0))),'coverage':state.coverage(scope)}
            if call.name=='android_device' and operation=='capabilities':
                saved=state.load();runtime=await diagnostics.capabilities() if saved and saved['scope']==scope and saved['status']=='running' else {'status':'not_running','requires_device_for_probe':True}
                actions=os.environ.get('ZEUS_ANDROID_ACTIONS_RUNTIME')=='1'
                return {'live_video':'websocket_fmp4_with_jpeg_fallback' if os.environ.get('ZEUS_ANDROID_TUNNEL')=='1' else 'webrtc',
                    'runtime':runtime,'capture_proxy':os.environ.get('ZEUS_ANDROID_CAPTURE_READY')=='1',
                    'capture_ca':os.environ.get('ZEUS_ANDROID_CA_TRUST','not_probed'),'audit_formats':['json','html','pdf'],
                    'static_analysis':['jadx','apktool','apksigner'],
                    'host_billing':'Actions uses job minutes until the bounded launcher ends the job.' if actions else 'Host VM billing does not stop when Android stops.'}
            if call.name=='android_device' and operation=='records':return diagnostics.records(scope,args.get('project',''))
            if call.name=='android_network' and operation=='coverage':return {'counters':state.coverage(scope),'body_limit_bytes':32768,'event_retention_limit':1000,'guarantee':'best_effort','limits':['TLS pinning, non-proxy traffic and dropped events may be missing.','Timing correlation does not prove an action caused a request.']}
            if call.name == "android_project" and operation in {"list", "job", "files", "read"}:
                return await projects.operation(scope, operation, args, device)
            if call.name == 'android_network' and operation in {'list', 'read'}:
                return network(scope, operation, args, value['role'])
            if call.name=='android_project' and operation!='install':
                # Static analysis never boots or requires an Android device.
                if not read_only:
                    state.db.execute('INSERT INTO operations VALUES(?,?,?,?)',(scope,call.request_id,digest,'{"uncertain":true}'));state.db.commit()
                result=await projects.operation(scope,operation,args,device)
                if not read_only:
                    state.db.execute('UPDATE operations SET value=? WHERE scope=? AND id=?',(json.dumps(result),scope,call.request_id));state.db.commit()
                return result
            if call.name == "android_device" and operation == "start":
                if value["role"] != "viewer": raise ValueError("Open the laboratory and start Android explicitly before using agent tools")
                if saved and saved["scope"] != scope and saved["status"] == "running": raise ValueError("Another conversation is using the Android device")
                if saved and saved["scope"] == scope and saved["status"] == "running": return await session(value)
            else:
                saved = state.owned(value,active=not (call.name == "android_device" and operation == "stop"))
                if clock() >= saved["deadline"]: await stop(saved, "time_limit"); raise ValueError("انتهت المدة المحددة للجلسة؛ افتح جلسة جديدة.")
                if not read_only and value["role"] == "agent" and (saved["controller"] != "agent" or clock() > saved["agent_until"]): raise ValueError("المستخدم يتحكم بالجهاز؛ سلّمه للوكيل من واجهة المختبر أولًا.")
                if not read_only and value["role"] == "viewer" and call.name != "android_device" and saved["controller"] != "human": raise ValueError("خذ التحكم من الوكيل أولًا")
            if not read_only:
                state.db.execute("INSERT INTO operations VALUES(?,?,?,?)", (scope, call.request_id, digest, '{"uncertain":true}')); state.db.commit()
            if call.name == "android_device":
                if operation == "start":
                    if saved and saved["scope"] != scope: await lifecycle.action("reset")
                    await lifecycle.action("start")
                    try: await device.connect()
                    except BaseException:
                        await lifecycle.action("stop"); raise
                    saved = {"scope":scope, "owner":value["sub"], "status":"running", "controller":"human", "agent_until":0,
                        "activity":clock(), "started":clock(), "deadline":min(clock()+1800,bootstrap['expires']) if bootstrap else clock()+1800, "capture":False,"trusted":bool(bootstrap and bootstrap.get("trusted"))}
                    if saved["trusted"]:saved.update(controller="agent",agent_until=saved["deadline"])
                    # Another conversation cannot inherit an earlier capture.
                    await device.command("shell", "settings", "put", "global", "http_proxy", ":0")
                elif operation == "stop": await stop(saved, "user")
                elif operation=='logs':return await diagnostics.logs(args)
                elif operation=='record_start':
                    result=await diagnostics.start(scope,args)
                    state.db.execute('UPDATE operations SET value=? WHERE scope=? AND id=?',(json.dumps(result),scope,call.request_id));state.db.commit()
                    return result
                elif operation=='record_stop':
                    result=await diagnostics.stop(scope)
                    state.db.execute('UPDATE operations SET value=? WHERE scope=? AND id=?',(json.dumps(result),scope,call.request_id));state.db.commit()
                    return result
                elif operation == 'trust':
                    if value['role']!='viewer':raise ValueError('Only the user can trust this session')
                    saved.update(trusted=True,controller='agent',agent_until=saved['deadline'])
                    state.record(scope,'session_trusted',{'actor':'viewer','expires':saved['deadline']})
                elif operation in {"take", "release"}:
                    if value["role"] != "viewer": raise ValueError("Only the user can transfer device control")
                    saved.update(controller="human" if operation == "take" else "agent", agent_until=clock()+1800)
                    if operation=="take":saved["trusted"]=False
                else: raise ValueError("Unknown session operation")
                state.save(saved); result = await session(value)
            elif call.name == "android_ui": result = await device.action(operation, args)
            elif call.name == "android_screenshot": result = {"image":{"mime":"image/jpeg", "data":base64.b64encode(await device.screenshot()).decode()}, "output":"Current Android screenshot"}
            elif call.name == "android_project": result = await projects.operation(scope, operation, args, device)
            elif call.name == "android_network":
                if operation in {"start", "stop"}:
                    if operation=='start' and os.environ.get('ZEUS_ANDROID_ACTIONS_RUNTIME')=='1' and os.environ.get('ZEUS_ANDROID_CAPTURE_READY')!='1':raise ValueError('Network observer is unavailable; no traffic capture has started')
                    proxy = os.environ.get("ZEUS_ANDROID_PROXY", "capture:8080") if operation == "start" else ":0"
                    await device.command("shell", "settings", "put", "global", "http_proxy", proxy)
                    saved["capture"] = operation == "start"; state.save(saved); notify()
                    result = {"capturing":saved["capture"], "https":"Requires a trusted certificate; pinned or non-proxy traffic may be unavailable"}
                else: raise ValueError("Unknown capture operation")
            else: raise ValueError("Unknown Android tool")
            current = state.load()
            if current and current["scope"] == scope: current["activity"] = clock(); state.save(current)
            if not read_only:
                state.db.execute("UPDATE operations SET value=? WHERE scope=? AND id=?", (json.dumps(result), scope, call.request_id))
                state.db.execute("DELETE FROM operations WHERE rowid NOT IN (SELECT rowid FROM operations ORDER BY rowid DESC LIMIT 500)"); state.db.commit()
            return result

    @app.post('/v1/tool')
    async def tool(call: Call, value=Depends(claims)):
        scope=state.scope(value);operation=call.arguments.get('operation','status')
        observe=call.name=='android_screenshot' or operation in {'status','timeline','capabilities','tree','list','read','job','files','report','search','compare','coverage','logs','records'}
        details={'request_id':call.request_id,'actor':value['role'],'tool':call.name,'operation':operation}
        if not observe:
            parameters={k:v for k,v in call.arguments.items() if k in {'project','variant','package','x','y','x2','y2','key','path'}}
            if 'text' in call.arguments:parameters['text_characters']=len(str(call.arguments['text']))
            state.record(scope,'action_started',{**details,'parameters':parameters});notify()
        task=asyncio.current_task()
        if value['role']=='agent' and not observe:active_agent[task]=scope
        try:result=await execute_tool(call,value)
        except asyncio.CancelledError:
            if not observe:state.record(scope,'action_interrupted',{**details,'reason':'manual_takeover_or_request_cancellation','uncertain':True});notify()
            return JSONResponse({'detail':'تم إيقاف الإجراء؛ افحص الجهاز قبل تكراره.','uncertain':True},409)
        except BaseException as error:
            if not observe:state.record(scope,'action_failed',{**details,'error':str(error)[:1000]});notify()
            raise
        finally:active_agent.pop(task,None)
        if not observe:state.record(scope,'action_finished',details);notify()
        return result

    @app.post('/v1/control/take')
    async def take_control(value=Depends(claims)):
        if value['role']!='viewer':raise HTTPException(403)
        saved=state.owned(value,active=False);saved.update(controller='human',agent_until=0,trusted=False);state.save(saved)
        state.db.execute('DELETE FROM consents WHERE scope=?',(state.scope(value),));state.db.commit()
        # Do not wait behind a stalled ADB call holding the ordinary tool gate.
        for task,scope in list(active_agent.items()):
            if scope==state.scope(value):task.cancel()
        state.record(state.scope(value),'manual_takeover',{'actor':'viewer'});notify()
        return await session(value)

    @app.get('/v1/timeline')
    async def timeline(after:int=0,value=Depends(claims)):
        return {'events':state.history(state.scope(value),after),'coverage':state.coverage(state.scope(value))}

    @app.get('/v1/timeline/feed')
    async def timeline_feed(request:Request,after:int=0,value=Depends(claims)):
        if value['role']!='viewer':raise HTTPException(403)
        if len(observers)>=4:raise HTTPException(429,'Too many laboratory viewers')
        observer=asyncio.Event();observers.add(observer)
        async def events():
            cursor=max(0,after)
            try:
                while clock()<value['exp']:
                    observer.clear();batch=state.history(state.scope(value),cursor)
                    if batch:
                        for event in batch:
                            cursor=event['id'];yield 'id: '+str(cursor)+'\ndata: '+json.dumps(event,ensure_ascii=False)+'\n\n'
                        continue
                    if await request.is_disconnected():break
                    try:await asyncio.wait_for(observer.wait(),min(15,max(.01,value['exp']-clock())))
                    except asyncio.TimeoutError:yield ': heartbeat\n\n'
            finally:observers.discard(observer)
        return StreamingResponse(events(),media_type='text/event-stream',headers={'X-Accel-Buffering':'no','Cache-Control':'no-store, no-transform'})

    @app.get('/v1/projects/{identifier}/export')
    async def report_export(identifier:str,format:str='json',variant:str='original',value=Depends(claims)):
        if value['role']!='viewer':raise HTTPException(403)
        async with gate:
            scope=state.scope(value);root=projects.project(scope,identifier);report=projects.report(root,variant)
            report['runtime_correlations']=audit.correlate(report,state.all_events(scope))
            report['timeline']=state.all_history(scope)
            report['recordings']=diagnostics.records(scope,identifier)['records']
            report['coverage']['runtime_capture']={'retention':state.coverage(scope),'limits':'Bounded, best effort; no packet-level completeness guarantee.'}
        content,mime=await asyncio.to_thread(reports.export,report,format)
        return Response(content,media_type=mime,headers={'Content-Disposition':f'attachment; filename="zeus-report-{identifier}.{format}"'})

    @app.get('/v1/projects/{identifier}/evidence/{recording}')
    async def evidence_download(identifier:str,recording:str,value=Depends(claims)):
        if value['role']!='viewer':raise HTTPException(403)
        path,metadata=diagnostics.artifact(state.scope(value),identifier,recording)
        return FileResponse(path,media_type='application/octet-stream',filename=metadata['file'])

    @app.post("/v1/upload")
    async def upload(request: Request, value=Depends(claims)):
        if value["role"] != "viewer": raise HTTPException(403)
        async with gate:
            uploaded=await projects.upload(state.scope(value), request.stream(), unquote(request.headers.get("x-filename", "application.apk")))
            record(state.scope(value),'apk_uploaded',{'actor':'viewer','project':uploaded['id'],'sha256':uploaded['sha256'],'bytes':uploaded['bytes']})
            return uploaded

    @app.delete("/v1/session")
    async def delete_session(value=Depends(claims)):
        async with gate:
            scope=state.scope(value); saved=state.load()
            if saved and saved["scope"]==scope:
                await diagnostics.stop(scope)
                await video.close();await lifecycle.action("reset")
                state.db.execute("DELETE FROM state WHERE id=1")
            await projects.delete(scope)
            state.db.execute("DELETE FROM events WHERE scope=?",(scope,))
            state.db.execute("DELETE FROM operations WHERE scope=?",(scope,));state.db.commit()
            state.db.execute('DELETE FROM timeline WHERE scope=?',(scope,));state.db.execute('DELETE FROM counters WHERE scope=?',(scope,));state.db.commit()
            state.db.execute('DELETE FROM consents WHERE scope=?',(scope,));state.db.commit()
            state.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            notify()
        return {"deleted":True}

    @app.post("/v1/video")
    async def offer(request: Request, value=Depends(claims)):
        state.owned(value)
        body = await request.json()
        return await video.offer(body.get("sdp", ""), body.get("type", ""), state.scope(value))

    @app.get("/v1/ice")
    async def ice(value=Depends(claims)):
        return {"iceServers":ice_servers(state.scope(value))}

    @app.post("/v1/heartbeat")
    async def heartbeat(value=Depends(claims)):
        async with gate:
            saved = state.owned(value)
            # Viewer presence keeps the device awake, but never extends deadline.
            saved["activity"] = clock(); state.save(saved)
        return {"deadline":saved["deadline"]}

    @app.post("/internal/capture")
    async def capture(request: Request, x_capture_token: str = Header(default="")):
        expected = os.environ.get("ZEUS_ANDROID_CAPTURE_TOKEN", "")
        if len(expected) < 32 or not hmac.compare_digest(x_capture_token, expected): raise HTTPException(403)
        async with gate:
            saved = state.load(); event = await request.json()
            if not saved or saved["status"] != "running" or not saved["capture"]: return {"accepted":False}
            # Exclude flows started before this conversation/session.
            if not isinstance(event.get("started"), (int,float)) or event["started"] < saved["started"]: return {"accepted":False}
            identifier = state.capture(saved["scope"], event); notify()
            for key in ('observer_dropped_total','observer_delivery_failures_total'):
                count=event.get(key)
                if isinstance(count,int) and 0<=count<1_000_000_000:
                    state.db.execute('INSERT INTO counters VALUES(?,?,?) ON CONFLICT(scope,name) DO UPDATE SET value=MAX(value,excluded.value)',(saved['scope'],key,count))
            state.db.commit()
        return {"accepted":True, "id":identifier}

    return app
