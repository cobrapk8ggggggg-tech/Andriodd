import asyncio
from pathlib import Path
import ssl
import tempfile
import unittest
import httpx
from tls_origin import start_origin


class TLSFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def test_origin_requires_the_explicit_test_ca_and_verifies_tls(self):
        with tempfile.TemporaryDirectory() as directory:
            server,ca=start_origin(directory)
            try:
                async with httpx.AsyncClient(trust_env=False) as client:
                    with self.assertRaises(httpx.ConnectError):await client.post('https://127.0.0.1:8091/probe',content=b'not trusted')
                context=ssl.create_default_context(cafile=str(ca))
                async with httpx.AsyncClient(verify=context,trust_env=False) as client:
                    response=await client.post('https://127.0.0.1:8091/probe',content='مرحبا'.encode())
                    self.assertEqual(response.json(),{'received':'مرحبا'})
            finally:await asyncio.to_thread(server.shutdown);server.server_close()
