"""Live WebRTC video, not periodically refreshed screenshots or saved recordings."""
import asyncio
import fractions
import time
from .ice import servers


class Video:
    def __init__(self, device): self.device, self.peers, self.processes = device, set(), set()

    async def offer(self, sdp, kind, identity="android"):
        from aiortc import RTCPeerConnection, RTCSessionDescription, VideoStreamTrack, RTCConfiguration, RTCIceServer, RTCRtpSender
        import av
        import os
        if kind != "offer" or len(sdp) > 100000 or len(self.peers) >= 2: raise ValueError("Video session limit reached")
        server = self
        class Screen(VideoStreamTrack):
            def __init__(self): super().__init__(); self.queue = asyncio.Queue(maxsize=1); self.task = asyncio.create_task(self.read()); self.origin = time.monotonic(); self.last_frame = 0
            async def read(self):
                try:
                    while self.readyState == "live":
                        process = await asyncio.create_subprocess_exec(*server.device.argv("exec-out", "screenrecord", "--output-format=h264", "--bit-rate", "1500000", "--size", "720x1280", "-"), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                        server.processes.add(process); codec = av.CodecContext.create("h264", "r")
                        try:
                            while data := await process.stdout.read(65536):
                                for packet in codec.parse(data):
                                    for frame in codec.decode(packet):
                                        frame.pts = int((time.monotonic()-self.origin)*90000); frame.time_base = fractions.Fraction(1, 90000)
                                        if self.queue.full(): self.queue.get_nowait()
                                        self.queue.put_nowait(frame)
                        finally:
                            if process.returncode is None: process.kill()
                            await process.wait(); server.processes.discard(process)
                        await asyncio.sleep(.2)
                except asyncio.CancelledError: pass
                except Exception: self.stop()
            async def recv(self):
                try:
                    await asyncio.sleep(max(0,1/15-(time.monotonic()-self.last_frame)))
                    frame=await asyncio.wait_for(self.queue.get(),15);self.last_frame=time.monotonic();return frame
                except asyncio.TimeoutError: self.stop(); raise
            def stop(self):
                super().stop()
                if asyncio.current_task() is not self.task: self.task.cancel()
        ice = [RTCIceServer(**entry) for entry in servers(identity)]
        peer = RTCPeerConnection(RTCConfiguration(iceServers=ice)); self.peers.add(peer); track = Screen()
        @peer.on("connectionstatechange")
        async def changed():
            if peer.connectionState in {"failed", "closed", "disconnected"}: track.stop(); await peer.close(); self.peers.discard(peer)
        try:
            await peer.setRemoteDescription(RTCSessionDescription(sdp=sdp, type=kind)); peer.addTrack(track)
            codecs=RTCRtpSender.getCapabilities("video").codecs
            preferred=[c for c in codecs if c.mimeType.lower()=="video/h264"]
            for transceiver in peer.getTransceivers():
                if transceiver.kind=="video": transceiver.setCodecPreferences(preferred+[c for c in codecs if c not in preferred])
            answer = await peer.createAnswer(); await peer.setLocalDescription(answer)
            return {"sdp": peer.localDescription.sdp, "type": peer.localDescription.type}
        except BaseException:
            track.stop(); await peer.close(); self.peers.discard(peer); raise

    async def close(self):
        await asyncio.gather(*(p.close() for p in list(self.peers)), return_exceptions=True); self.peers.clear()
        for process in list(self.processes):
            if process.returncode is None: process.kill()
