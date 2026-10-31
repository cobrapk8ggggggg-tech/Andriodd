import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from zeus_android import sealed

class SealedTests(unittest.TestCase):
    def setUp(self):
        self.key=X25519PrivateKey.generate();self.private=self.key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        self.public=sealed.b64(self.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw));self.session=str(uuid.uuid4())
    def test_private_readiness_roundtrip_and_wrong_key_or_session_is_rejected(self):
        data=b'{"bootstrap":"not-for-public-artifacts"}'
        value=sealed.seal(data,self.public,self.session);self.assertNotIn('not-for-public-artifacts',json.dumps(value));self.assertEqual(sealed.open_envelope(value,self.private),data)
        with self.assertRaises(InvalidTag):sealed.open_envelope(value,os.urandom(32))
        value['session']=str(uuid.uuid4())
        with self.assertRaises(InvalidTag):sealed.open_envelope(value,self.private)
    def test_chunked_archive_tamper_and_truncation_never_leave_partial_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'project';encrypted=root/'encrypted';restored=root/'restored';data=os.urandom(2*sealed.CHUNK+17);source.write_bytes(data)
            meta=sealed.seal_file(source,encrypted,self.public,self.session);self.assertEqual(meta['chunks'],3)
            sealed.open_file(encrypted,restored,self.private);self.assertEqual(restored.read_bytes(),data);restored.unlink()
            restored.write_bytes(b'keep-existing')
            with self.assertRaises(FileExistsError):sealed.open_file(encrypted,restored,self.private)
            self.assertEqual(restored.read_bytes(),b'keep-existing');restored.unlink()
            raw=bytearray(encrypted.read_bytes());raw[-1]^=1;encrypted.write_bytes(raw)
            with self.assertRaises(InvalidTag):sealed.open_file(encrypted,restored,self.private)
            self.assertFalse(restored.exists());encrypted.write_bytes(raw[:-20])
            with self.assertRaises(ValueError):sealed.open_file(encrypted,restored,self.private)
            self.assertFalse(restored.exists())
