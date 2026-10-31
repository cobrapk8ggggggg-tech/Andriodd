"""Real H.264 -> WebRTC transport, with synthetic frames, not a fake Android."""
import asyncio
import io
from pathlib import Path
import sys
import tempfile
import unittest
import av
from aiortc import RTCPeerConnection, RTCConfiguration, RTCSessionDescription
from zeus_android.video import Video


class VideoTests(unittest.IsolatedAsyncioTestCase):
    async def test_live_h264_reaches_a_real_webrtc_peer_and_closes_processes(self):
        stream=io.BytesIO()
        container=av.open(stream,mode='w',format='h264');encoder=container.add_stream('libx264',rate=10)
        encoder.width=64;encoder.height=96;encoder.pix_fmt='yuv420p';encoder.options={'tune':'zerolatency','preset':'ultrafast'}
        for i in range(20):
            frame=av.VideoFrame(64,96,'yuv420p')
            for p in frame.planes:p.update(bytes([80])*p.buffer_size)
            for packet in encoder.encode(frame):container.mux(packet)
        for packet in encoder.encode():container.mux(packet)
        container.close()
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'video.h264';file.write_bytes(stream.getvalue())
            class Source:
                def argv(self,*args):
                    return [sys.executable,'-u','-c',"import sys,time; d=open(sys.argv[1],'rb').read();\nwhile True:\n sys.stdout.buffer.write(d);sys.stdout.buffer.flush();time.sleep(.1)",str(file)]
            server=Video(Source());client=RTCPeerConnection(RTCConfiguration(iceServers=[]));seen=asyncio.Future()
            @client.on('track')
            def track(track):
                async def receive():
                    try:
                        frame=await track.recv()
                        if not seen.done():seen.set_result((frame.width,frame.height))
                    except Exception as e:
                        if not seen.done():seen.set_exception(e)
                asyncio.create_task(receive())
            try:
                client.addTransceiver('video',direction='recvonly');await client.setLocalDescription(await client.createOffer())
                answer=await server.offer(client.localDescription.sdp,'offer')
                await client.setRemoteDescription(RTCSessionDescription(**answer))
                self.assertEqual(await asyncio.wait_for(seen,20),(64,96))
            finally:await client.close();await server.close();await asyncio.sleep(.1)
            self.assertFalse(server.peers);self.assertTrue(all(p.returncode is not None for p in server.processes))
