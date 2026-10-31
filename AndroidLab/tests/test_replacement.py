"""Signing mismatch recovery must never uninstall an unrelated application."""
from pathlib import Path
import tempfile
import unittest
import uuid
from zeus_android.projects import Projects


class ReplacementTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.projects = Projects(Path(self.temp.name) / 'projects')
        self.scope = 'a' * 64;self.identifier = str(uuid.uuid4())
        self.root = self.projects.root / self.scope / self.identifier
        (self.root / 'work/decoded').mkdir(parents=True)
        (self.root / 'project.json').write_text('{}')
        (self.root / 'original.apk').write_bytes(b'original')
        (self.root / 'rebuilt.apk').write_bytes(b'rebuilt')
        (self.root / 'work/decoded/AndroidManifest.xml').write_text('<manifest package="com.zeus.lab.probe"><application/></manifest>')
        self.calls = []

    async def install(self, error='INSTALL_FAILED_UPDATE_INCOMPATIBLE', replacement=False, fail_modified=False):
        test = self
        class Device:
            async def command(self, *args, **kw):
                test.calls.append(args)
                if args[:2] == ('install', '-r'):raise ValueError(error)
                if fail_modified and args == ('install', test.root / 'rebuilt.apk'):raise ValueError('INSTALL_FAILED_INVALID_APK')
                return b'Success'
        return await self.projects.operation(self.scope, 'install',
            {'project': self.identifier, 'variant': 'rebuilt', 'replace_existing': replacement}, Device())

    async def test_signing_change_requires_explicit_replacement_and_preserves_files(self):
        with self.assertRaisesRegex(ValueError, 'INSTALL_REQUIRES_REPLACEMENT'):await self.install()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual((self.root / 'original.apk').read_bytes(), b'original')

    async def test_abi_or_other_install_failure_never_triggers_uninstall(self):
        with self.assertRaisesRegex(ValueError, 'NO_MATCHING_ABIS'):await self.install('INSTALL_FAILED_NO_MATCHING_ABIS', True)
        self.assertEqual(len(self.calls), 1)

    async def test_replacement_uses_apk_identity_and_reports_data_reset(self):
        result = await self.install(replacement=True)
        self.assertEqual(self.calls[1], ('uninstall', 'com.zeus.lab.probe'))
        self.assertTrue(result['replaced_existing']);self.assertTrue(result['device_app_data_reset'])
        self.assertEqual((self.root / 'original.apk').read_bytes(), b'original')

    async def test_failed_replacement_restores_original_and_reports_data_loss(self):
        with self.assertRaisesRegex(ValueError, 'restored=True.*App data was reset'):
            await self.install(replacement=True, fail_modified=True)
        self.assertEqual(self.calls[-1], ('install', self.root / 'original.apk'))
