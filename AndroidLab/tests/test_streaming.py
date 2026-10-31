"""Real codec/MP4 transport from a synthetic H.264 process, not an Android claim."""
import asyncio
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import av
from zeus_android.streaming import SocketVideo


class StreamingTests(unittest.IsolatedAsyncioTestCase):
    async def test_remux_produces_decodable_fragmented_mp4_without_reencoding(self):
        raw=io.BytesIO();container=av.open(raw,'w',format='h264');encoder=container.add_stream('libx264',rate=10)
        encoder.width=64;encoder.height=96;encoder.pix_fmt='yuv420p';encoder.options={'tune':'zerolatency','preset':'ultrafast','profile':'baseline'}
        for i in range(40):
            frame=av.VideoFrame(64,96,'yuv420p')
            for plane in frame.planes:plane.update(bytes([i*3])*plane.buffer_size)
            for packet in encoder.encode(frame):container.mux(packet)
        for packet in encoder.encode():container.mux(packet)
        container.close()
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'input.h264';source.write_bytes(raw.getvalue())
            class Source:
                def argv(self,*args):return [sys.executable,'-u','-c','import sys,time;d=open(sys.argv[1],"rb").read();\nwhile True:\n sys.stdout.buffer.write(d);sys.stdout.buffer.flush();time.sleep(.05)',str(source)]
            video=SocketVideo(Source());generator=video.fragments();data=bytearray();metadata=None
            try:
                async with asyncio.timeout(15):
                    async for value in generator:
                        if isinstance(value,dict):
                            self.assertNotIn('error',value,value);metadata=value
                        else:data.extend(value)
                        if data.count(b'moof')>=3:break
            finally:await generator.aclose();await video.close()
            self.assertEqual(metadata['mode'],'fmp4');self.assertIn('avc1.',metadata['mime']);self.assertIn(b'ftyp',data);self.assertIn(b'moov',data)
            decoded=av.open(io.BytesIO(data),format='mp4');frame=next(decoded.decode(video=0));self.assertEqual((frame.width,frame.height),(64,96));decoded.close()
            self.assertFalse(video.processes)
