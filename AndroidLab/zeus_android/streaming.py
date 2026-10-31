"""H.264 -> fragmented MP4 without re-encoding; bounded HTTPS/WS transport."""
import asyncio
import fractions
import io
import os
import signal
import subprocess
import threading
import time


class SocketVideo:
    def __init__(self,device):self.device=device;self.processes=set();self.tasks=set()

    async def fragments(self):
        import av
        loop=asyncio.get_running_loop();queue=asyncio.Queue(maxsize=8);stopped=threading.Event();process_ref=[]
        def deliver(value):
            if stopped.is_set():raise RuntimeError('Video connection closed')
            future=asyncio.run_coroutine_threadsafe(queue.put(value),loop)
            try:future.result(timeout=3)
            except BaseException:future.cancel();raise
        class Sink(io.RawIOBase):
            position=0
            def writable(self):return True
            def seekable(self):return False
            def tell(self):return self.position
            def write(self,data):
                for at in range(0,len(data),65536):deliver(bytes(data[at:at+65536]))
                self.position+=len(data);return len(data)
        def produce():
            process=None
            try:
                env={k:os.environ[k] for k in ('PATH','HOME','LANG') if k in os.environ}
                process=subprocess.Popen(self.device.argv('exec-out','screenrecord','--output-format=h264','--bit-rate','1000000','--size','720x1280','--time-limit','180','-'),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,start_new_session=True,bufsize=0)
                process_ref.append(process);self.processes.add(process)
                with av.open(process.stdout,format='h264',options={'probesize':'2048','analyzeduration':'0'}) as source:
                    incoming=source.streams.video[0];extra=incoming.codec_context.extradata or b'';codec='avc1.42E01E'
                    if len(extra)>=4 and extra[0]==1:codec='avc1.'+extra[1:4].hex()
                    else:
                        for start in (b'\x00\x00\x00\x01\x67',b'\x00\x00\x01\x67'):
                            at=extra.find(start)
                            if at>=0 and len(extra)>=at+len(start)+3:codec='avc1.'+extra[at+len(start):at+len(start)+3].hex();break
                    deliver({'mode':'fmp4','mime':'video/mp4; codecs="'+codec+'"','width':incoming.width,'height':incoming.height})
                    with av.open(Sink(),'w',format='mp4',options={'movflags':'empty_moov+default_base_moof+frag_keyframe','frag_duration':'250000'}) as output:
                        stream=output.add_stream_from_template(incoming);stream.time_base=fractions.Fraction(1,90000)
                        origin=time.monotonic();last=-3000
                        for packet in source.demux(incoming):
                            if stopped.is_set():break
                            if not packet.size:continue
                            last=max(last+3000,int((time.monotonic()-origin)*90000))
                            packet.pts=packet.dts=last;packet.duration=3000;packet.time_base=fractions.Fraction(1,90000);packet.stream=stream
                            output.mux(packet)
            except BaseException as error:
                if not stopped.is_set():
                    try:deliver({'error':type(error).__name__,'fallback':'frames'})
                    except BaseException:pass
            finally:
                if process:
                    if process.poll() is None:
                        try:os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                    process.wait()
                    if process.stdout:process.stdout.close()
                    self.processes.discard(process)
                if not stopped.is_set():
                    try:deliver(None)
                    except BaseException:pass
        task=asyncio.create_task(asyncio.to_thread(produce));self.tasks.add(task)
        try:
            while True:
                value=await asyncio.wait_for(queue.get(),20)
                if value is None:break
                yield value
        finally:
            stopped.set()
            for process in process_ref:
                if process.poll() is None:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
            try:await asyncio.wait_for(asyncio.shield(task),5)
            except (asyncio.TimeoutError,asyncio.CancelledError):task.cancel()
            self.tasks.discard(task)

    async def close(self):
        for process in list(self.processes):
            if process.poll() is None:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
        for task in list(self.tasks):task.cancel()
        await asyncio.gather(*list(self.tasks),return_exceptions=True)
