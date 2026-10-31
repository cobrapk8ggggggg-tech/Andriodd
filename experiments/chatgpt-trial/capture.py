"""Passive, bounded observation of the test guest; never bypasses app TLS checks."""
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit
from zeus_android.capture import Capture

class Recorder(Capture):
    def __init__(self):super().__init__();self.count=0;self.size=0;self.epoch=None
    def emit(self,event):
        # Google Play background downloads must not exhaust the trial's budget.
        # This experiment records OpenAI endpoints and its Sentry reporting only,
        # plus the independent TLS fixture before the application phase begins.
        address=event.get('url','')
        host=(urlsplit(address if '://' in address else '//'+address).hostname or event.get('sni') or '').lower()
        if not any(host==domain or host.endswith('.'+domain) for domain in ('openai.com','chatgpt.com','sentry.io','zeus-probe.invalid','127.0.0.1')):return
        epoch_path=Path(os.environ['CHATGPT_CAPTURE_FILE']).with_suffix('.epoch')
        epoch=epoch_path.read_text() if epoch_path.exists() else 'tls-control'
        if epoch!=self.epoch:self.epoch=epoch;self.count=0;self.size=0
        for field in ('request_headers','response_headers'):
            if field in event:
                event[field]={k:('[redacted]' if any(s in k.lower() for s in ('api-key','authorization','cookie')) else v) for k,v in event[field].items()}
        event={'timestamp':time.time(),**event};raw=(json.dumps(event,ensure_ascii=False)+'\n').encode()
        if self.count>=1500 or self.size+len(raw)>8*1024*1024:return
        self.count+=1;self.size+=len(raw)
        with open(os.environ['CHATGPT_CAPTURE_FILE'],'ab') as output:output.write(raw)
    def http_connect(self,flow):
        self.emit({'phase':'connect','method':'CONNECT','url':flow.request.pretty_url,'flow_id':flow.id})
    def tls_failed_client(self,data):
        self.emit({'phase':'tls_failed_client','sni':data.context.client.sni,'error':str(data.context.client.error)[:600]})
    def tls_failed_server(self,data):
        self.emit({'phase':'tls_failed_server','sni':data.context.client.sni,'error':str(data.context.server.error)[:600]})

addons=[Recorder()]
