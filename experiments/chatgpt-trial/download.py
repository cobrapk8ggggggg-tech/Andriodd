"""Fetch a pinned bundle; verify every APK against OpenAI's published signing key."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import zipfile

BUNDLE=json.loads(Path(__file__).with_name('public-source.json').read_text())['url']
SHA256='38cd3cbec61a59da3a4c7b2c6d7242dcabaaa2fb04245810d0510369012df892'
SIGNER='b24f4bfbb3cf293f938703b9d87027c1102cc36dc4fa206910e08927db40473c'
SOURCE='https://openai.com/.well-known/assetlinks.json'

def fetch(url,path,limit):
    request=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'})
    with urllib.request.urlopen(request,timeout=40) as response,path.open('wb') as output:
        size=0
        while chunk:=response.read(1024*1024):
            size+=len(chunk)
            if size>limit:raise ValueError('Download exceeds limit')
            output.write(chunk)

def prepare(root):
    root=Path(root);root.mkdir(parents=True,exist_ok=True);bundle=root/'chatgpt.xapk'
    fetch(BUNDLE,bundle,256*1024**2)
    if hashlib.sha256(bundle.read_bytes()).hexdigest()!=SHA256:raise ValueError('Bundle changed; review and repin before installing')
    tools=root/'tools.zip';fetch('https://dl.google.com/android/repository/build-tools_r35_linux.zip',tools,62000000)
    if hashlib.sha1(tools.read_bytes()).hexdigest()!='2cfaa0bbb2336e9ec18ed3ecea84fa2e2af607bc':raise ValueError('Build-tools checksum mismatch')
    jar=root/'apksigner.jar'
    with zipfile.ZipFile(tools) as z:jar.write_bytes(z.read(next(n for n in z.namelist() if n.endswith('/lib/apksigner.jar'))))
    paths=[];signatures={}
    with zipfile.ZipFile(bundle) as z:
        manifest=json.loads(z.read('manifest.json'))
        if manifest['package_name']!='com.openai.chatgpt' or manifest['version_code']!='2629319':raise ValueError('Unexpected application/version')
        for name in z.namelist():
            if not name.endswith('.apk'):continue
            if Path(name).name!=name:raise ValueError('Unsafe bundle path')
            path=root/name;path.write_bytes(z.read(name))
            result=subprocess.run(['java','-jar',str(jar),'verify','--print-certs',str(path)],capture_output=True,text=True,check=True,timeout=40,env={k:os.environ[k] for k in ['PATH','HOME','LANG','JAVA_HOME'] if k in os.environ})
            signer=next(line.split(': ',1)[1].strip().lower() for line in result.stdout.splitlines() if 'certificate SHA-256 digest:' in line)
            if signer!=SIGNER:raise ValueError('APK signer does not match official OpenAI asset links')
            paths.append(path);signatures[name]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'signer':signer}
    return paths,{'package':manifest['package_name'],'version':manifest['version_name'],'version_code':manifest['version_code'],'min_sdk':manifest['min_sdk_version'],'bundle_sha256':SHA256,'download_source':'APKPure public CDN (data.winudf.com)','signer_authority':SOURCE,'apks':signatures}
