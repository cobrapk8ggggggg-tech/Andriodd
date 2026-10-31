"""Consistent bounded snapshots, independent of the session transport keys."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import shutil
import os
import re

MAX_ARCHIVE = 1024**3
MAX_CONTENTS = 1536 * 1024**2


def snapshot(data, destination, session, sequence, final):
    data, destination = Path(data), Path(destination)
    total = 0;count = 0
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        database = Path(temporary) / 'state.sqlite3'
        source = sqlite3.connect(data / 'state.sqlite3');copy = sqlite3.connect(database)
        try:source.backup(copy)
        finally:copy.close();source.close()
        database_bytes=database.stat().st_size
        with tarfile.open(destination, 'w:gz', compresslevel=1) as archive:
            for path in sorted(data.rglob('*')):
                relative = path.relative_to(data)
                if (not path.is_file() or path.is_symlink() or relative.parts[0] == 'signing'
                        or relative.parts[0].startswith('state.sqlite3')):continue
                count += 1;total += path.stat().st_size
                if count > 60000 or total > MAX_CONTENTS:raise ValueError('Session archive exceeds its 1.5 GiB contents limit')
                archive.add(path, arcname=str(relative), recursive=False)
                if destination.stat().st_size > MAX_ARCHIVE:raise ValueError('Compressed session archive exceeds 1 GiB')
            archive.add(database, arcname='state.sqlite3', recursive=False)
    if destination.stat().st_size > MAX_ARCHIVE:raise ValueError('Compressed session archive exceeds 1 GiB')
    hasher=hashlib.sha256()
    with destination.open('rb') as file:
        while block:=file.read(1024*1024):hasher.update(block)
    return {'version':1,'session':session,'sequence':sequence,'final':final,'bytes':destination.stat().st_size,
            'contents_bytes':total+database_bytes,
            'files':count+1,'sha256':hasher.hexdigest(),'format':'tar.gz','signing_key_included':False}


def restore_projects(archive_path, projects, scope):
    """Import immutable APKs/work/reports; never replace the live database."""
    if not re.fullmatch('[a-f0-9]{64}',scope):raise ValueError('Invalid destination scope')
    with tempfile.TemporaryDirectory(dir=projects.root.parent) as temporary:
        staging=Path(temporary);total=0;count=0
        with tarfile.open(archive_path,'r:gz') as archive:
            for entry in archive:
                parts=entry.name.split('/')
                if (entry.name.startswith('/') or '\\' in entry.name or any(p in {'','..','.'} for p in parts)
                        or not entry.isfile() or entry.size<0):raise ValueError('Archive contains unsafe entries')
                total+=entry.size;count+=1
                if total>MAX_CONTENTS or count>60000:raise ValueError('Archive exceeds restore limits')
                # Preserve historical records as an inert file; a supplied SQLite
                # database is never opened or substituted for the active session.
                if parts[0]!='projects':continue
                if len(parts)<4 or not re.fullmatch('[a-f0-9]{64}',parts[1]) or not re.fullmatch('[a-f0-9-]{36}',parts[2]):raise ValueError('Invalid archived project identity')
                target=staging.joinpath(*parts[1:]);target.parent.mkdir(parents=True,exist_ok=True)
                if target.exists():raise ValueError('Duplicate archive entry')
                with archive.extractfile(entry) as source,target.open('xb') as output:shutil.copyfileobj(source,output,1024*1024)
        incoming=list(staging.glob('*/*/project.json'))
        if not incoming:raise ValueError('This archive contains no projects')
        if len(incoming)+len(projects.list(scope))>10:raise ValueError('Too many projects for one session')
        prepared=[];identifiers=set()
        for metadata in incoming:
            if metadata.stat().st_size>100000:raise ValueError('Archived project metadata is oversized')
            root=metadata.parent;identifier=root.name;value=json.loads(metadata.read_text())
            if value.get('id')!=identifier or not (root/'original.apk').is_file():raise ValueError('Archived project metadata is incomplete')
            hasher=hashlib.sha256()
            with (root/'original.apk').open('rb') as source:
                while block:=source.read(1024*1024):hasher.update(block)
            if value.get('sha256')!=hasher.hexdigest():raise ValueError('Archived original APK hash did not match')
            target=projects.root/scope/identifier
            if target.exists() or identifier in identifiers:raise ValueError('The project already exists; it was not overwritten')
            identifiers.add(identifier)
            prepared.append((root,target,value))
        moved=[]
        try:
            for source,target,value in prepared:
                target.parent.mkdir(parents=True,exist_ok=True);shutil.move(str(source),str(target));moved.append(target)
                (target/'original.apk').chmod(0o400)
                # Jobs interrupted at snapshot time are not successful builds.
                for path in (target/'jobs').glob('*.json'):
                    job=json.loads(path.read_text())
                    if job.get('status')=='running':job['status']='interrupted';path.write_text(json.dumps(job))
                uid=int(os.environ['ZEUS_ANDROID_BUILD_UID']) if os.environ.get('ZEUS_ANDROID_BUILD_UID') else None
                if uid is not None and (target/'work').exists():
                    for path in [target/'work',*(target/'work').rglob('*')]:os.chown(path,uid,uid)
            return {'projects':[value for _,_,value in prepared],'restored':True,
                    'active_database_replaced':False,'limitation':'Project files and reports restored; previous session timeline remains in the saved archive.'}
        except BaseException:
            for target in moved:shutil.rmtree(target)
            raise
