"""Human takeover is independent of a blocked ordinary Actions tool request."""
import asyncio
import hashlib
import hmac
import json
import time
import uuid
from cryptography.exceptions import InvalidTag
import httpx

from .sealed import open_envelope


class EmergencyMailbox:
    def __init__(self, path, session, private_key, viewer_secret, viewer_token, client, publish, on_error=None):
        self.path, self.session, self.private_key = path, session, private_key
        self.viewer_secret, self.viewer_token = viewer_secret, viewer_token
        self.client, self.publish, self.on_error = client, publish, on_error
        self.seen = ''
        self.count = 0
        self.requests = set()

    async def check(self):
        if not self.path.is_file() or self.path.is_symlink():
            return
        if self.path.stat().st_size > 256000:
            raise ValueError('Emergency request exceeds limit')
        raw = self.path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if self.seen == digest:
            return
        self.seen = digest
        outer = json.loads(raw)
        if not outer.get('payload'):
            return
        if outer.get('session') != self.session:
            raise ValueError('Emergency request belongs to another session')
        command = json.loads(open_envelope(outer['payload'], self.private_key))
        if command.get('name') != '__take' or not isinstance(command.get('credential'), str) or not hmac.compare_digest(command['credential'], self.viewer_secret):
            raise ValueError('Only the viewer can reclaim device control')
        request = str(uuid.UUID(command['request_id']))
        if request in self.requests:
            return
        self.requests.add(request)
        response = await self.client.post('/v1/control/take', headers={'Authorization': 'Bearer ' + self.viewer_token()}, json={})
        self.count += 1
        self.publish(self.count, {'request_id': request, 'http_status': response.status_code,
                                 'result': response.json(), 'observed_at': time.time(), 'session': self.session})

    async def run(self, stop, deadline):
        while not stop.is_set() and time.time() < deadline:
            try:
                await self.check()
            except (ValueError, TypeError, KeyError, OSError, InvalidTag, httpx.HTTPError) as error:
                if self.on_error:
                    self.on_error({'error': type(error).__name__, 'detail': str(error)[:1000]})
            try:
                await asyncio.wait_for(stop.wait(), 1)
            except asyncio.TimeoutError:
                pass
