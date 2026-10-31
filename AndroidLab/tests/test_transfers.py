import hashlib
from pathlib import Path
import tempfile
import unittest
import httpx
from zeus_android.transfers import asset_url, download_asset


class TransferTests(unittest.IsolatedAsyncioTestCase):
    async def test_release_asset_is_streamed_verified_and_does_not_receive_account_credentials(self):
        value = b'an actual bounded transfer';digest = hashlib.sha256(value).hexdigest()
        def serve(request):
            self.assertNotIn('authorization', request.headers)
            return httpx.Response(200, content=value)
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'application.apk'
            async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as client:
                result = await download_asset('https://release-assets.githubusercontent.com/one?signature=temporary', digest, target, 100, client)
            self.assertEqual(result['bytes'], len(value));self.assertEqual(target.read_bytes(), value)

    async def test_partial_or_oversized_assets_are_removed_and_redirects_are_not_followed(self):
        for response in [httpx.Response(200, content=b'wrong'), httpx.Response(200, content=b'a'*101),
                         httpx.Response(302, headers={'Location': 'https://another.invalid'})]:
            with self.subTest(status=response.status_code), tempfile.TemporaryDirectory() as temporary:
                target=Path(temporary)/'incoming.apk'
                async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request:response)) as client:
                    with self.assertRaises(ValueError):await download_asset('https://release-assets.githubusercontent.com/one', 'a'*64, target, 100, client)
                self.assertFalse(target.exists())

    async def test_only_github_release_download_hosts_are_used(self):
        for value in ['http://release-assets.githubusercontent.com/a','https://release-assets.githubusercontent.com.evil/a',
                      'https://user@release-assets.githubusercontent.com/a','https://127.0.0.1/a']:
            with self.assertRaises(ValueError):asset_url(value)
