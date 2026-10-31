"""End-to-end modification of our repository's own controlled test APK."""
import asyncio
import base64
import json
import re
from verify_capture import verify_capture


async def verify_rebuild(call, device, observer, data, project):
    async def operation(name, **extra):
        return await call('android_project', {'operation': name, 'project': project, **extra})

    async def job(name, **extra):
        started = await operation(name, **extra)
        for _ in range(180):
            state = await operation('job', job=started['id'])
            if state['status'] != 'running':
                if state['status'] != 'completed':
                    raise ValueError('Actual APK ' + name + ' failed: ' + str(state))
                return state
            await asyncio.sleep(2)
        raise ValueError('Actual APK ' + name + ' did not finish within acceptance deadline')

    await job('decode')
    files = (await operation('files'))['files']
    selected = None
    for path in files:
        if path.endswith('.smali') and '/com/zeus/lab/probe/' in path:
            entry = await operation('read', path=path)
            if 'https://zeus-probe.invalid:8091/probe' in entry['content']:
                selected = entry
                break
    if not selected:
        raise ValueError('The controlled HTTPS method was not found in decoded smali')
    content = selected['content']
    methods = list(re.finditer(r'(?ms)^\.method\b.*?^\.end method', content))
    method = next(m for m in methods if 'https://zeus-probe.invalid:8091/probe' in m.group())
    local = re.search(r'(?m)^\s*\.locals (\d+)\s*$', method.group())
    if not local or int(local[1]) < 2:
        raise ValueError('The controlled diagnostic fixture needs two local registers')
    marker = 'ZEUS_REBUILT_HTTPS_DIAGNOSTIC'
    injection = ('\n    const-string v0, "ZEUSLabDiagnostic"\n'
                 '    const-string v1, "' + marker + '"\n'
                 '    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I\n')
    offset = method.start() + local.end()
    await operation('write', path=selected['path'], expected_sha256=selected['sha256'],
                    content=content[:offset] + injection + content[offset:])
    await job('build')
    installation = await operation('install', variant='rebuilt', replace_existing=True)
    await call('android_ui', {'operation': 'launch', 'package': 'com.zeus.lab.probe'})
    rebuilt_evidence = data / 'rebuilt-runtime';rebuilt_evidence.mkdir()
    original_request = json.loads((data / 'actual-https-request.json').read_text())
    expected = base64.b64decode(original_request['request_body']['base64']).decode()
    network = await verify_capture(call, device, observer, rebuilt_evidence, expected=expected)
    logs = (await device.command('logcat', '-d', '-s', 'ZEUSLabDiagnostic:I', '*:S')).decode(errors='replace')
    (rebuilt_evidence / 'diagnostic-logcat.txt').write_text(logs)
    if marker not in logs:
        raise ValueError('The rebuilt APK did not emit the injected diagnostic at runtime')
    await job('audit', variant='rebuilt')
    comparison = await operation('compare')
    if not comparison['original_preserved'] or comparison['original_sha256'] == comparison['rebuilt_sha256']:
        raise ValueError('Rebuilt/original APK evidence is inconsistent')
    result = {'passed': True, 'diagnostic_executed': True, 'modified_path': selected['path'],
              'installation': installation, 'actual_https_capture': network, 'comparison': comparison}
    (data / 'actual-rebuild.json').write_text(json.dumps(result, indent=2))
    return result
