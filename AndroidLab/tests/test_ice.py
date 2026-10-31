import base64
import hashlib
import hmac
import json
import os
import unittest
from unittest.mock import patch
from zeus_android.ice import servers


class ICETests(unittest.TestCase):
    def test_browser_and_worker_receive_expiring_credentials_without_the_shared_secret(self):
        secret='turn-test-secret-not-production-'+'x'*32
        with patch.dict(os.environ,{'ZEUS_ANDROID_STUN_URL':'stun:stun.test','ZEUS_ANDROID_TURN_URL':'turns:relay.test:5349','ZEUS_ANDROID_TURN_SECRET':secret}):
            value=servers('scope',now=1000);again=servers('scope',now=1301)
        turn=value[1]
        self.assertTrue(turn['username'].startswith('1300:'));self.assertNotEqual(turn['credential'],again[1]['credential'])
        self.assertNotIn(secret,json.dumps(value))
        self.assertEqual(turn['credential'],base64.b64encode(hmac.new(secret.encode(),turn['username'].encode(),hashlib.sha1).digest()).decode())
