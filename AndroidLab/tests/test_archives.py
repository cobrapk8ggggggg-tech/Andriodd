import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest
import hashlib
import io
import uuid
from zeus_android.archives import snapshot,restore_projects
from zeus_android.projects import Projects


class ArchiveTests(unittest.TestCase):
    def test_snapshot_has_consistent_database_and_original_but_no_signing_key_or_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);data=root/'data';data.mkdir()
            db=sqlite3.connect(data/'state.sqlite3');db.execute('PRAGMA journal_mode=WAL');db.execute('CREATE TABLE test(value)');db.execute('INSERT INTO test VALUES(42)');db.commit()
            (data/'projects').mkdir();(data/'projects/original.apk').write_bytes(b'original APK')
            (data/'signing').mkdir();(data/'signing/lab.keystore').write_bytes(b'private signing identity')
            (data/'escape').symlink_to('/etc/passwd')
            target=root/'checkpoint.tar.gz';metadata=snapshot(data,target,'session',99,True)
            with tarfile.open(target) as archive:
                self.assertEqual(sorted(archive.getnames()),['projects/original.apk','state.sqlite3'])
                saved=root/'saved.sqlite3';saved.write_bytes(archive.extractfile('state.sqlite3').read())
            with sqlite3.connect(saved) as copy:self.assertEqual(copy.execute('SELECT value FROM test').fetchone()[0],42)
            self.assertFalse(metadata['signing_key_included']);self.assertEqual(metadata['bytes'],target.stat().st_size)
            self.assertGreater(metadata['contents_bytes'],len(b'original APK'));db.close()

    def fixture(self,root):
        data=root/'data';data.mkdir();db=sqlite3.connect(data/'state.sqlite3');db.execute('CREATE TABLE test(value)');db.close()
        identifier=str(uuid.uuid4());project=data/'projects'/('a'*64)/identifier;(project/'jobs').mkdir(parents=True)
        (project/'original.apk').write_bytes(b'original');(project/'jobs'/('b'*36+'.json')).write_text('{"status":"running"}')
        (project/'project.json').write_text(json.dumps({'id':identifier,'sha256':hashlib.sha256(b'original').hexdigest()}))
        archive=root/'snapshot.tar.gz';snapshot(data,archive,'test',99,True)
        return archive,identifier

    def test_restore_verifies_original_and_marks_interrupted_jobs_without_replacing_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);archive,identifier=self.fixture(root);projects=Projects(root/'new/projects')
            result=restore_projects(archive,projects,'c'*64)
            self.assertTrue(result['restored']);self.assertFalse(result['active_database_replaced'])
            project=projects.project('c'*64,identifier)
            self.assertEqual((project/'original.apk').read_bytes(),b'original')
            self.assertEqual(json.loads(next((project/'jobs').glob('*.json')).read_text())['status'],'interrupted')
            with self.assertRaisesRegex(ValueError,'already exists'):restore_projects(archive,projects,'c'*64)
            self.assertEqual((project/'original.apk').read_bytes(),b'original')

    def test_restore_rejects_escape_links_and_wrong_apk_hash_before_importing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);archive,identifier=self.fixture(root);projects=Projects(root/'new/projects')
            for name,link in [('../escape',False),('projects/escape',True)]:
                bad=root/'bad.tar.gz'
                with tarfile.open(bad,'w:gz') as output:
                    entry=tarfile.TarInfo(name)
                    if link:entry.type=tarfile.SYMTYPE;entry.linkname='/etc/passwd';output.addfile(entry)
                    else:entry.size=1;output.addfile(entry,io.BytesIO(b'x'))
                with self.assertRaisesRegex(ValueError,'unsafe'):restore_projects(bad,projects,'c'*64)
            metadata=root/'data/projects'/('a'*64)/identifier/'project.json';metadata.write_text(json.dumps({'id':identifier,'sha256':'0'*64}))
            snapshot(root/'data',root/'wrong.tar.gz','test',99,True)
            with self.assertRaisesRegex(ValueError,'hash'):restore_projects(root/'wrong.tar.gz',projects,'c'*64)
            self.assertEqual(projects.list('c'*64),[])
