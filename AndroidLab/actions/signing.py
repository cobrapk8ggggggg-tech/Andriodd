"""A disposable signing identity for test APKs, never a production key."""
import asyncio
import os


async def prepare_signing_key(data):
    directory=data/'signing';directory.mkdir(mode=0o711);directory.chmod(0o711)
    key=directory/'lab.keystore'
    process=await asyncio.create_subprocess_exec('keytool','-genkeypair','-noprompt','-keystore',str(key),
        '-storetype','JKS','-storepass','android','-keypass','android','-alias','zeus-lab',
        '-keyalg','RSA','-keysize','2048','-validity','3650','-dname','CN=ZEUS Android Lab,OU=Testing',
        env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':'/tmp','LANG':'C.UTF-8',
             'JAVA_TOOL_OPTIONS':'-Xmx256m -XX:ActiveProcessorCount=2'},
        stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
    try:
        code=await asyncio.wait_for(process.wait(),45)
    finally:
        if process.returncode is None:process.kill();await process.wait()
    if code!=0 or not key.is_file():raise ValueError('The disposable APK signing identity could not be created')
    os.chown(key,-1,10002);key.chmod(0o440)
    os.environ['ZEUS_ANDROID_KEYSTORE']=str(key)
