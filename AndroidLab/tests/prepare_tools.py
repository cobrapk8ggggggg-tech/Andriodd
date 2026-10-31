"""Pinned, checksum-verified CI tools; no production credentials or installations."""
import hashlib
from pathlib import Path
import urllib.request
import zipfile
import os

root=Path(os.environ.get('LAB_TOOLS_DIR','/tmp/zeus-android-tools'));root.mkdir(exist_ok=True)
downloads=[('https://github.com/iBotPeaches/Apktool/releases/download/v2.11.1/apktool_2.11.1.jar','apktool.jar','56d59c524fc764263ba8d345754d8daf55b1887818b15cd3b594f555d249e2db'),('https://github.com/skylot/jadx/releases/download/v1.5.3/jadx-1.5.3.zip','jadx.zip','8280f3799c0273fe797a2bcd90258c943e451fd195f13d05400de5e6451d15ec')]
for url,name,digest in downloads:
    target=root/name
    with urllib.request.urlopen(url,timeout=60) as response:target.write_bytes(response.read())
    assert hashlib.sha256(target.read_bytes()).hexdigest()==digest
with zipfile.ZipFile(root/'jadx.zip') as z:z.extractall(root/'jadx')
(root/'apktool').write_text('#!/bin/sh\nexec java -Xmx1536m -jar '+str(root/'apktool.jar')+' "$@"\n');(root/'apktool').chmod(0o755)
(root/'jadx/bin/jadx').chmod(0o755)
print('Pinned Apktool and JADX checksums verified')
