"""Install only pinned official emulator, platform tools and API29 image archives."""
import hashlib
from pathlib import Path
import shutil
import tempfile
import urllib.request
import zipfile

PACKAGES = [
 ('https://dl.google.com/android/repository/emulator-linux_x64-16740729.zip',349658551,'f41f9e31eb5ca64926603c03265c50bbc0ff4172','/opt/android-sdk'),
 ('https://dl.google.com/android/repository/platform-tools_r37.0.1-linux.zip',9054187,'477254aa5f903c15cf51001717bdf347fb6b53e0','/opt/android-sdk'),
 ('https://dl.google.com/android/repository/sys-img/android/x86_64-29_r08-linux.zip',689676765,'e4b798d6fcddff90d528d74ef22ce3dd4a2ca798','/opt/android-sdk/system-images/android-29/default'),
]

def main():
    for url,size,sha1,target in PACKAGES:
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'archive.zip';digest=hashlib.sha1();total=0
            with urllib.request.urlopen(url,timeout=45) as response,path.open('wb') as output:
                while block:=response.read(1024*1024):
                    total+=len(block)
                    if total>size:raise ValueError('Archive exceeds official size')
                    digest.update(block);output.write(block)
            if total!=size or digest.hexdigest()!=sha1:raise ValueError('Official SDK archive checksum/size mismatch')
            root=Path(target);root.mkdir(parents=True,exist_ok=True)
            with zipfile.ZipFile(path) as archive:
                for entry in archive.infolist():
                    destination=root/entry.filename
                    if not destination.resolve().is_relative_to(root.resolve()):raise ValueError('Unsafe archive path')
                    archive.extract(entry,root)
                    mode=entry.external_attr>>16
                    if mode&0o111:destination.chmod(0o755)
            print('Verified SDK archive:',url.rsplit('/',1)[-1],flush=True)
    Path('/opt/android-sdk/platforms').mkdir(exist_ok=True)

if __name__=='__main__':main()
