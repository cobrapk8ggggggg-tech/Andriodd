"""Evidence-based static inventory. Heuristics never become confirmed exploits."""
import hashlib
import json
from pathlib import Path
import re
import time
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
import zipfile

ANDROID = '{http://schemas.android.com/apk/res/android}'
RULES = [
    ('webview-js', 'JavaScript enabled in WebView', r'setJavaScriptEnabled\s*\(\s*true', 'Review untrusted content and exposed JavaScript bridges.'),
    ('webview-file', 'File access enabled in WebView', r'setAllow(?:UniversalAccessFromFileURLs|FileAccessFromFileURLs)\s*\(\s*true', 'Test whether untrusted pages can reach local or remote data.'),
    ('tls-verifier', 'Custom hostname verifier', r'(?:HostnameVerifier|setHostnameVerifier|checkServerTrusted)', 'Review the complete implementation; a symbol alone does not prove insecure TLS.'),
    ('js-bridge', 'JavaScript/native bridge', r'(?:addJavascriptInterface|@JavascriptInterface)', 'Review origin restrictions and reachable native operations.'),
    ('storage', 'Sensitive storage entry point', r'(?:getSharedPreferences|MODE_WORLD_READABLE|openOrCreateDatabase|EncryptedSharedPreferences)', 'Check the data stored and its access controls.'),
    ('auth', 'Authentication entry point', r'(?:Authorization|Bearer |OAuth|access_token|refresh_token)', 'Inspect token handling without copying credentials into a report.'),
    ('network', 'Network implementation', r'(?:okhttp3|HttpURLConnection|Retrofit|WebSocket|EventSource|CertificatePinner)', 'Correlate source evidence with observed traffic and TLS errors.'),
    ('crypto', 'Cryptography entry point', r'(?:Cipher\.getInstance|MessageDigest\.getInstance|SecretKeySpec)', 'Validate algorithms and key lifecycle in context.'),
]


def read_text(path, maximum=2_000_000):
    if path.is_symlink() or path.stat().st_size > maximum: raise ValueError('Source file exceeds analysis limit')
    return path.read_text(errors='replace')


def manifest_inventory(path):
    text = read_text(path)
    if '<!DOCTYPE' in text or '<!ENTITY' in text: raise ValueError('Manifest entities are not accepted')
    root = ET.fromstring(text)
    application = root.find('application')
    sdk = root.find('uses-sdk')
    result = {'package':root.get('package'), 'version_name':root.get(ANDROID+'versionName'),
              'version_code':root.get(ANDROID+'versionCode'), 'min_sdk':sdk.get(ANDROID+'minSdkVersion') if sdk is not None else None,
              'target_sdk':sdk.get(ANDROID+'targetSdkVersion') if sdk is not None else None,
              'permissions':sorted({e.get(ANDROID+'name') for e in root.findall('uses-permission') if e.get(ANDROID+'name')}),
              'application':{}, 'components':[]}
    if application is not None:
        result['application'] = {k.removeprefix(ANDROID):v for k,v in application.attrib.items()}
        for kind in ('activity','activity-alias','service','receiver','provider'):
            for element in application.findall(kind):
                explicit = element.get(ANDROID+'exported')
                result['components'].append({'kind':kind,'name':element.get(ANDROID+'name'),
                    'exported':explicit, 'has_intent_filter':element.find('intent-filter') is not None,
                    'permission':element.get(ANDROID+'permission') or application.get(ANDROID+'permission'),
                    'read_permission':element.get(ANDROID+'readPermission'), 'write_permission':element.get(ANDROID+'writePermission'),
                    'authorities':element.get(ANDROID+'authorities'), 'exported_resolution':'explicit' if explicit is not None else 'requires_sdk_and_component_context'})
    return result


def source_index(roots, query=None, maximum=300):
    if query is not None and (not isinstance(query,str) or not 2 <= len(query) <= 200): raise ValueError('Search needs 2..200 characters')
    matches=[]; endpoints=[]; libraries=set(); files=0; total=0; skipped=0
    patterns=[(key,title,re.compile(pattern),recommendation) for key,title,pattern,recommendation in RULES]
    limit_hit=False
    for label, root in roots.items():
        if not root.is_dir():continue
        for path in sorted(root.rglob('*')):
            if not path.is_file() or path.is_symlink() or path.suffix not in {'.java','.kt','.smali','.xml','.json','.properties'}: continue
            size=path.stat().st_size
            if size>1_000_000: skipped+=1;continue
            if files>=4000 or total+size>64*1024*1024: limit_hit=True;break
            files+=1;total+=size
            name=label+'/'+str(path.relative_to(root)); raw=path.read_bytes();digest=hashlib.sha256(raw).hexdigest()
            for number,line in enumerate(raw.decode(errors='replace').splitlines(),1):
                if len(line)>20000:continue
                for match in re.finditer(r'https?://[^\s\"\'<>\\)]+',line):
                    value=match.group()[:1000];url=urlsplit(value)
                    try:port=url.port
                    except ValueError:continue
                    if url.hostname and len(endpoints)<500:
                        # Query/user-info can contain credentials; never persist it.
                        endpoints.append({'endpoint':url.scheme+'://'+url.hostname+((':'+str(port)) if port else '')+url.path,'source':name,'line':number,'sha256':digest})
                if line.lstrip().startswith('import '):
                    namespace=line.strip()[7:].split(';')[0].split('.')
                    if len(namespace)>=2: libraries.add('.'.join(namespace[:3]))
                if len(matches)>=maximum:continue
                if query is not None:
                    if query.casefold() in line.casefold():matches.append({'rule':'search','source':name,'line':number,'sha256':digest,'excerpt':line.strip()[:250]})
                else:
                    for key,title,pattern,recommendation in patterns:
                        if pattern.search(line):
                            matches.append({'rule':key,'title':title,'source':name,'line':number,'sha256':digest,
                                'classification':'observation','confidence':'heuristic','recommendation':recommendation})
                            break
        if limit_hit:break
    return {'matches':matches,'endpoints':list({(e['endpoint'],e['source'],e['line']):e for e in endpoints}.values()),
            'library_namespaces':sorted(libraries)[:300],'coverage':{'files_scanned':files,'bytes_scanned':total,'oversized_files_skipped':skipped,'scan_limit_reached':limit_hit,'match_limit_reached':len(matches)>=maximum}}


def analyze(apk, decoded, sources, metadata, signature_output=''):
    inventory=manifest_inventory(decoded/'AndroidManifest.xml')
    index=source_index({'sources':sources,'decoded':decoded})
    with zipfile.ZipFile(apk) as archive:
        dex=[{'name':x.filename,'bytes':x.file_size} for x in archive.infolist() if re.fullmatch(r'classes\d*\.dex',x.filename)]
        native=[{'name':x.filename,'bytes':x.file_size} for x in archive.infolist() if x.filename.startswith('lib/') and x.filename.endswith('.so')][:300]
    observations=[]
    for field in ('debuggable','usesCleartextTraffic','allowBackup'):
        if inventory['application'].get(field)=='true':
            observations.append({'id':'manifest-'+field,'title':field+' is enabled','classification':'observation','confidence':'manifest_fact',
                'evidence':{'file':'AndroidManifest.xml','attribute':field,'value':'true'},'recommendation':'Review intended build configuration and validate actual exposure before reporting a vulnerability.'})
    for component in inventory['components']:
        if component['exported']=='true' and not component['permission'] and not component['read_permission'] and not component['write_permission']:
            observations.append({'id':'exported-'+str(component['name']),'title':'Exported component without a declared permission',
                'classification':'unresolved','confidence':'manifest_fact','evidence':component,
                'recommendation':'Check component behavior and caller validation in an authorized runtime test; exported alone is not an exploit.'})
    return {'schema_version':1,'generated_at':time.time(),'artifact':{**metadata,'sha256':hashlib.sha256(apk.read_bytes()).hexdigest()},
            'inventory':inventory,'dex':dex,'native_libraries':native,'signature_verification':signature_output[-8000:],
            'findings':observations,'source_observations':index,
            'coverage':{'static_analysis':'completed_with_explicit_limits','dynamic_analysis':'not_performed_by_static_audit',
                'confirmed_vulnerabilities':0,'limits':['Decompiled code can be incomplete or obfuscated.','Library namespaces are indicators, not verified dependency versions.','No vulnerability is confirmed by these heuristics.']}}


def correlate(report, events):
    endpoints=report.get('source_observations',{}).get('endpoints',[])
    links=[];seen=set()
    for event in events:
        url=urlsplit(event.get('url',''))
        if not url.hostname:continue
        key=(event.get('flow_id'),url.hostname,url.path)
        if key in seen:continue
        seen.add(key)
        evidence=[e for e in endpoints if urlsplit(e['endpoint']).hostname==url.hostname][:20]
        links.append({'flow_id':event.get('flow_id'),'endpoint':url.scheme+'://'+url.hostname+url.path,
                      'status':event.get('status'),'source_candidates':evidence,'relationship':'host_match_only' if evidence else 'no_static_match'})
        if len(links)>=200:break
    return links
