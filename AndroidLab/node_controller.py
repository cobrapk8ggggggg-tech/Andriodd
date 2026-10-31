#!/usr/bin/env python3
"""Host-only control of one fixed container. Bind only to the private lab bridge.
Stopping the Android container releases its CPU/RAM, not the host VM's bill.
"""
import hmac
import json
import os
import subprocess
import threading
import datetime
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


gate=threading.Lock()

def enforce_deadline():
    # The worker is not responsible for its own crash recovery. This fixed
    # host watchdog also caps Android container uptime when the API is down.
    with gate:
        result=subprocess.run(["docker","inspect","--format","{{json .State}}","zeus-lab-android"],capture_output=True,timeout=5)
        if result.returncode: return
        value=json.loads(result.stdout)
        if not value.get("Running"): return
        started=datetime.datetime.fromisoformat(value["StartedAt"].replace("Z","+00:00")).timestamp()
        if time.time()-started>=1800: subprocess.run(["docker","stop","--time","5","zeus-lab-android"],capture_output=True,timeout=15)

def watchdog():
    while True:
        try: enforce_deadline()
        except (OSError,ValueError,KeyError,subprocess.TimeoutExpired): pass
        time.sleep(15)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        key=os.environ.get("ZEUS_ANDROID_NODE_TOKEN", "")
        if len(key)<32 or not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer "+key): self.send_error(403);return
        commands={"/start":[["docker","start","zeus-lab-android"]],"/stop":[["docker","stop","--time","5","zeus-lab-android"]],"/reset":[]}
        if self.path not in commands: self.send_error(404);return
        try:
            with gate:
                selected=commands[self.path][:]
                if self.path=="/reset":
                    if subprocess.run(["docker","inspect","zeus-lab-android"],capture_output=True,timeout=5).returncode==0: selected.append(["docker","rm","-f","zeus-lab-android"])
                    if subprocess.run(["docker","volume","inspect","zeus-lab-android-data"],capture_output=True,timeout=5).returncode==0: selected.append(["docker","volume","rm","zeus-lab-android-data"])
                    selected.append(["docker","compose","-f","/opt/zeus/AndroidLab/compose.yaml","--profile","device","create","android"])
                ok=all(subprocess.run(command,capture_output=True,timeout=30,check=False).returncode==0 for command in selected)
        except (OSError,subprocess.TimeoutExpired): ok=False
        self.send_response(200 if ok else 503);self.send_header("Content-Type","application/json");self.end_headers()
        self.wfile.write(json.dumps({"ok":ok}).encode())


if __name__=="__main__":
    threading.Thread(target=watchdog,daemon=True).start()
    ThreadingHTTPServer((os.environ.get("ZEUS_ANDROID_NODE_BIND","172.31.80.1"),9090),Handler).serve_forever()
