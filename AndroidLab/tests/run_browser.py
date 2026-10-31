"""Run reproducible layout/import checks without pretending Android is booted."""
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
import httpx
from zeus_android.tokens import encode

root=Path(__file__).resolve().parents[2]
proof=Path(os.environ.get('LAB_PROOF_DIR','android-results'));proof.mkdir(exist_ok=True,parents=True)
with tempfile.TemporaryDirectory() as directory:
    key=secrets.token_urlsafe(40)
    env={**os.environ,'PYTHONPATH':str(root/'AndroidLab'),'LAB_TEST_KEY':key,'LAB_TEST_TOKEN':encode(key,'ui-test',str(uuid.uuid4())),
         'LAB_PROOF_DIR':str(proof.resolve()),'LAB_TEST_APK':directory+'/fixture.apk'}
    with zipfile.ZipFile(env['LAB_TEST_APK'],'w') as z:z.writestr('AndroidManifest.xml',b'fixture manifest');z.writestr('classes.dex',b'fixture dex')
    with (proof/'ui-server.log').open('w') as log:
        process=subprocess.Popen([sys.executable,'AndroidLab/tests/preview_server.py'],cwd=root,env=env,stdout=log,stderr=log)
        try:
            for i in range(100):
                try:
                    if httpx.get('http://127.0.0.1:8769/health',timeout=1).status_code==200:break
                except httpx.HTTPError:time.sleep(.1)
            subprocess.run(['node','AndroidLab/tests/browser.cjs'],cwd=root,env=env,timeout=80,check=True)
        finally:process.terminate();process.wait(timeout=5)
