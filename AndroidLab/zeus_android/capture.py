"""Bounded, passive request/stream/WebSocket observations sent to the worker."""
import asyncio
import base64
import json
import os
import time
import urllib.request

LIMIT = 32768


def headers(value):
    # Both count and values are bounded; unusual headers cannot evade the event cap.
    return {k[:80]: ('[redacted]' if any(part in k.lower() for part in ('authorization','cookie','api-key','sentinel-payload','conduit-token')) else v[:1024]) for k, v in list(value.items())[:24]}


def body(raw, total=None, available=True):
    raw = raw or b''
    count = len(raw) if total is None else total
    return {'base64': base64.b64encode(raw[:LIMIT]).decode(), 'bytes': count if available else None,
            'truncated': not available or count > LIMIT, 'available': available}


class Capture:
    def __init__(self): self.pending = set();self.dropped=0;self.delivery_failures=0

    def event(self, flow, phase, **extra):
        sequence = flow.metadata.get('zeus_sequence', 0) + 1
        flow.metadata['zeus_sequence'] = sequence
        event = {'flow_id': flow.id, 'sequence': sequence, 'phase': phase,
                 'started': flow.request.timestamp_start, 'observed': time.time(),
                 'method': flow.request.method, 'url': flow.request.pretty_url[:4000],
                 'duration_ms':round(max(0,time.time()-flow.request.timestamp_start)*1000,3),
                 'status': flow.response.status_code if flow.response else None,
                 'request_headers': headers(flow.request.headers),
                 'request_body': body(flow.request.raw_content, available=flow.request.raw_content is not None), **extra}
        self.emit(event)

    def emit(self, event):
        if len(self.pending) >= 16:self.dropped+=1;return
        event={**event,'observer_dropped_total':self.dropped,'observer_delivery_failures_total':self.delivery_failures}
        task = asyncio.create_task(self.send(event))
        self.pending.add(task); task.add_done_callback(self.pending.discard)

    def request(self, flow):
        self.event(flow, 'request', request_headers=headers(flow.request.headers),
                   request_body=body(flow.request.raw_content, available=flow.request.raw_content is not None))

    def responseheaders(self, flow):
        self.event(flow, 'headers', response_headers=headers(flow.response.headers))
        # Stream these protocols unchanged; never wait for their connection to close.
        content_type = flow.response.headers.get('content-type', '').lower()
        live = any(t in content_type for t in ('text/event-stream', 'ndjson', 'application/grpc'))
        preview = bytearray(); total = 0; previous = 0; emitted = 0; ended=False
        def stream(chunk):
            nonlocal total, previous, emitted, ended
            total += len(chunk)
            room = LIMIT - len(preview)
            if room: preview.extend(chunk[:room])
            now = time.monotonic()
            if not chunk and not ended or chunk and live and emitted < 64 and (not emitted or room and now - previous >= .5):
                self.event(flow, 'stream' if chunk else 'complete', response_body=body(bytes(preview), total),
                           response_headers=headers(flow.response.headers))
                previous = now; emitted += 1
                if not chunk:ended=True
            return chunk  # No alteration or replay of the application traffic.
        flow.metadata['zeus_stream'] = True
        flow.response.stream = stream

    def response(self, flow):
        if flow.metadata.get('zeus_stream'): return
        self.event(flow, 'complete', request_headers=headers(flow.request.headers),
                   response_headers=headers(flow.response.headers),
                   request_body=body(flow.request.raw_content, available=flow.request.raw_content is not None),
                   response_body=body(flow.response.raw_content, available=flow.response.raw_content is not None))

    def error(self, flow):
        self.event(flow, 'error', error=str(flow.error)[:500])

    def http_connect(self,flow):
        self.event(flow,'connect')

    def tls_failed_client(self,data):
        self.emit({'phase':'tls_failed_client','started':getattr(data.context.client,'timestamp_start',None) or time.time(),
            'sni':data.context.client.sni,'error':str(data.context.client.error)[:500],
            'interpretation':'Client TLS negotiation failed; pinning is one possible cause, not a confirmed diagnosis.'})

    def tls_failed_server(self,data):
        self.emit({'phase':'tls_failed_server','started':getattr(data.context.client,'timestamp_start',None) or time.time(),
            'sni':data.context.client.sni,'error':str(data.context.server.error)[:500],
            'interpretation':'Upstream TLS negotiation failed. No certificate verification was disabled.'})

    def websocket_message(self, flow):
        message = flow.websocket.messages[-1]
        self.event(flow, 'websocket', direction='outgoing' if message.from_client else 'incoming',
                   message_type='text' if message.is_text else 'binary', response_body=body(message.content))
        # mitmproxy otherwise retains the entire long-lived WebSocket history.
        del flow.websocket.messages[:-1]

    async def send(self, event):
        def deliver():
            request = urllib.request.Request(os.environ.get('ZEUS_ANDROID_CAPTURE_ENDPOINT', 'http://worker:8080/internal/capture'),
                data=json.dumps(event, ensure_ascii=False).encode(), headers={'Content-Type':'application/json', 'X-Capture-Token':os.environ['ZEUS_ANDROID_CAPTURE_TOKEN']})
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as response: response.read(1000)
        try: await asyncio.to_thread(deliver)
        except (OSError, KeyError): self.delivery_failures+=1

addons = [Capture()]
