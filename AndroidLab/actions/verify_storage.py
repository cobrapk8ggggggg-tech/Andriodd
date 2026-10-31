"""Real GitHub asset round trip; this tests storage, not Android execution."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import uuid
import zipfile
from zeus_android.archives import snapshot,restore_projects,MAX_ARCHIVE
from zeus_android.projects import Projects,MAX_APK
from zeus_android.transfers import download_asset


async def main():
    operation,folder=sys.argv[1:];root=Path(folder);scope='a'*64
    if operation=='prepare':
        source=root/'original.apk'
        with zipfile.ZipFile(source,'w',compression=zipfile.ZIP_STORED) as archive:
            archive.writestr('AndroidManifest.xml','<manifest package="com.zeus.storage.fixture"/>')
            # Deliberately larger than the former 25 MiB checkpoint limit.
            archive.writestr('assets/controlled-storage-fixture.bin',os.urandom(26*1024*1024))
        value={'bytes':source.stat().st_size,'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}
        (root/'input.json').write_text(json.dumps(value));return
    transfer=json.loads((root/'transfer.json').read_text())
    if operation=='import':
        source=root/'downloaded.apk';await download_asset(transfer['url'],transfer['sha256'],source,MAX_APK)
        projects=Projects(root/'data/projects')
        async def chunks():
            with source.open('rb') as file:
                while block:=file.read(256*1024):yield block
        project=await projects.upload(scope,chunks(),'controlled-storage-fixture.apk')
        db=sqlite3.connect(root/'data/state.sqlite3');db.execute('CREATE TABLE test(value)');db.execute('INSERT INTO test VALUES(1)');db.commit();db.close()
        metadata=snapshot(root/'data',root/'checkpoint.tar.gz',str(uuid.uuid4()),99,True)
        (root/'checkpoint.json').write_text(json.dumps(metadata));(root/'project.json').write_text(json.dumps(project));return
    if operation=='restore':
        source=root/'restored.tar.gz';await download_asset(transfer['url'],transfer['sha256'],source,MAX_ARCHIVE)
        projects=Projects(root/'restored/projects');restored=restore_projects(source,projects,'b'*64)
        original=json.loads((root/'input.json').read_text());project=restored['projects'][0]
        if project['sha256']!=original['sha256']:raise ValueError('Restored APK digest did not match the original file')
        print(json.dumps({'passed':True,'bytes':original['bytes'],'original_sha256':original['sha256'],'restored_sha256':project['sha256'],'archive_exceeds_former_25MiB_limit':source.stat().st_size>25*1024**2,'active_database_replaced':restored['active_database_replaced']}))

asyncio.run(main())
