"""Actual HTTPS request observation before the controlled server replies."""
import asyncio
import base64
import json
import re
import uuid


async def verify_capture(call, device, observer, data, expected=None):
    expected = expected or 'مرحبا ZEUS ' + str(uuid.uuid4())
    observer.origin.received.clear();observer.origin.replied.clear();observer.origin.release.clear()
    await call('android_network', {'operation': 'start'})
    cursor = 0
    while True:
        previous = (await call('android_network', {'operation': 'list', 'after': cursor, 'limit': 50}))['events']
        if not previous:break
        cursor = previous[-1]['id']
    width, height = await device.size()

    async def point(description):
        tree = await call('android_ui', {'operation': 'tree'})
        node = next(n for n in tree['nodes'] if n.get('content-desc') == description)
        left, top, right, bottom = map(int, re.findall(r'\d+', node['bounds']))
        return {'x': (left + right) / (2 * width), 'y': (top + bottom) / (2 * height)}

    await call('android_ui', {'operation': 'tap', **await point('probeInput')})
    await call('android_ui', {'operation': 'type', 'text': expected})
    await call('android_ui', {'operation': 'tap', **await point('probeSend')})
    request, response = None, None
    for _ in range(100):
        events = (await call('android_network', {'operation': 'list', 'after': cursor, 'limit': 50}))['events']
        for event in events:
            cursor = event['id']
            if event.get('url', '').endswith('/probe') and event.get('phase') == 'request':
                request = event
                break
        if request:break
        await asyncio.sleep(.2)
    if not request:
        raise ValueError('The actual Android HTTPS request was not observed')
    async def detail(event):
        values=(await call('android_network', {'operation':'read','after':event['id']-1}))['events']
        if not values or values[0]['id']!=event['id']:raise ValueError('The selected capture event was evicted before its details were read')
        return values[0]
    request=await detail(request)
    if base64.b64decode(request['request_body']['base64']).decode() != expected or observer.origin.replied.is_set():
        raise ValueError('The request body was incorrect or capture waited for the full response')
    observer.origin.release.set()
    for _ in range(100):
        events = (await call('android_network', {'operation': 'list', 'after': cursor, 'limit': 50}))['events']
        for event in events:
            cursor = event['id']
            if event.get('flow_id') == request['flow_id'] and event.get('phase') == 'complete':
                response = event
                break
        if response:break
        await asyncio.sleep(.2)
    if not response or response.get('status') != 200 or not response.get('url', '').startswith('https://'):
        raise ValueError('The actual Android HTTPS response was not verified')
    response=await detail(response)
    captured=base64.b64decode(response.get('response_body',{}).get('base64',''))
    if json.loads(captured).get('received')!=expected:raise ValueError('The actual HTTPS response body did not echo the original Android message')
    (data / 'actual-https-request.json').write_text(json.dumps(request, ensure_ascii=False))
    (data / 'actual-https-response.json').write_text(json.dumps(response, ensure_ascii=False))
    await call('android_network', {'operation': 'stop'})
    return {'passed': True, 'source': 'actual Android HTTPS POST', 'unicode_body_matched': True,
            'request_observed_before_response': True, 'status': 200, 'third_party_pinning_tested': False}
