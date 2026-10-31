"""Protocol hooks must observe bytes immediately without changing app traffic."""
import base64
from types import SimpleNamespace as NS
import unittest
from zeus_android.capture import Capture, LIMIT

class CaptureTests(unittest.TestCase):
    def flow(self):
        return NS(id='flow-1',metadata={},request=NS(timestamp_start=123,method='POST',pretty_url='https://test.invalid/chat',headers={'Authorization':'private','Content-Type':'text/plain'},raw_content='مرحبا'.encode()),response=None)
    def test_request_precedes_response_and_stream_is_passive_bounded_and_immediate(self):
        addon=Capture();events=[];addon.emit=events.append;flow=self.flow()
        addon.request(flow)
        self.assertEqual(events[0]['phase'],'request');self.assertIsNone(events[0]['status'])
        self.assertEqual(events[0]['request_headers']['Authorization'],'[redacted]')
        flow.response=NS(status_code=200,headers={'content-type':'text/event-stream'},raw_content=None)
        addon.responseheaders(flow);chunk=b'data: first\n\n'
        self.assertIs(flow.response.stream(chunk),chunk)
        self.assertEqual(events[-1]['phase'],'stream');self.assertEqual(base64.b64decode(events[-1]['response_body']['base64']),chunk)
        huge=b'a'*(LIMIT*2);self.assertIs(flow.response.stream(huge),huge)
        self.assertEqual(flow.response.stream(b''),b'');addon.response(flow)
        self.assertEqual(events[-1]['phase'],'complete');self.assertTrue(events[-1]['response_body']['truncated'])
        self.assertEqual(len(base64.b64decode(events[-1]['response_body']['base64'])),LIMIT)
        self.assertEqual(events[-1]['response_body']['bytes'],len(chunk)+len(huge))
        self.assertEqual([e['sequence'] for e in events],list(range(1,len(events)+1)))
    def test_websocket_direction_and_retained_history_are_bounded(self):
        addon=Capture();events=[];addon.emit=events.append;flow=self.flow();message=NS(content=b'hello',from_client=True,is_text=True)
        flow.websocket=NS(messages=[message]*200);addon.websocket_message(flow)
        self.assertEqual(len(flow.websocket.messages),1);self.assertEqual(events[0]['direction'],'outgoing')
        self.assertEqual(base64.b64decode(events[0]['response_body']['base64']),b'hello')
