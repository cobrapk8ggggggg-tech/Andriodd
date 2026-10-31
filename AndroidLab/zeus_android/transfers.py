"""Bounded downloads from a single short-lived GitHub release asset URL."""
import hashlib
import re
from urllib.parse import urlsplit
import httpx


def asset_url(value):
    if not isinstance(value, str) or len(value) > 16000:
        raise ValueError('Invalid release asset URL')
    url = urlsplit(value)
    if (url.scheme != 'https' or url.hostname not in {'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
            or url.username or url.password or url.port not in (None, 443) or url.fragment):
        raise ValueError('Use the signed download URL for this private GitHub release asset')
    return value


async def download_asset(url, digest, target, maximum, client=None):
    asset_url(url)
    if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError('The release asset needs its expected SHA-256')
    transport = client or httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=180)
    total = 0;hasher = hashlib.sha256()
    try:
        async with transport.stream('GET', url, headers={'Accept': 'application/octet-stream'}) as response:
            if response.status_code != 200:
                raise ValueError('Private release download failed: HTTP ' + str(response.status_code))
            length = response.headers.get('content-length')
            if length and int(length) > maximum:raise ValueError('Release asset exceeds the transfer limit')
            with target.open('xb') as output:
                async for block in response.aiter_bytes(256 * 1024):
                    total += len(block)
                    if total > maximum:raise ValueError('Release asset exceeds the transfer limit')
                    hasher.update(block);output.write(block)
        if total == 0 or hasher.hexdigest() != digest:
            raise ValueError('Release asset SHA-256 did not match')
        return {'bytes': total, 'sha256': digest}
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    finally:
        if client is None:await transport.aclose()
