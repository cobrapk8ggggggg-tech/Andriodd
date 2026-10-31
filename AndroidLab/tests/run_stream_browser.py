"""Real browser MSE/WS acceptance using synthetic H264, never a fake Android claim."""
import asyncio,io,json,os,secrets,socket,sys,tempfile,time,uuid
from pathlib import Path
import av,uvicorn
from zeus_android.app import create_app
from zeus_android.tokens import encode
async def main():
 with tempfile.TemporaryDirectory() as directory:
  root=Path(directory);data=io.BytesIO();container=av.open(data,'w',format='h264');encoder=container.add_stream('libx264',rate=10)
  encoder.width=64;encoder.height=96;encoder.pix_fmt='yuv420p';encoder.options={'tune':'zerolatency','preset':'ultrafast','profile':'baseline'}
  for i in range(30):
   frame=av.VideoFrame(64,96,'yuv420p')
   for plane in frame.planes:plane.update(bytes([40+i*3])*plane.buffer_size)
   for packet in encoder.encode(frame):container.mux(packet)
  for packet in encoder.encode():container.mux(packet)
  container.close();source=root/'source.h264';source.write_bytes(data.getvalue())
  class Source:
   def argv(self,*args):return [sys.executable,'-u','-c','import sys,time;d=open(sys.argv[1],"rb").read();\nwhile True:\n sys.stdout.buffer.write(d);sys.stdout.buffer.flush();time.sleep(.1)',str(source)]
  os.environ['ZEUS_ANDROID_TUNNEL']='1';key=secrets.token_urlsafe(40);conversation=str(uuid.uuid4());app=create_app(root=root/'state',key=key,owner='synthetic-transport',device=Source())
  claims={'sub':'synthetic-transport','conversation':conversation};now=time.time();app.state.lab.save({'scope':app.state.lab.scope(claims),'owner':claims['sub'],'status':'running','controller':'human','agent_until':0,'capture':False,'started':now,'activity':now,'deadline':now+180})
  listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();port=listener.getsockname()[1]
  server=uvicorn.Server(uvicorn.Config(app,log_level='error',access_log=False));serving=asyncio.create_task(server.serve(sockets=[listener]))
  try:
   while not server.started:await asyncio.sleep(.02)
   env={**os.environ,'LAB_STREAM_URL':f'http://127.0.0.1:{port}/lab/','LAB_TEST_TOKEN':encode(key,claims['sub'],conversation)}
   process=await asyncio.create_subprocess_exec('node','AndroidLab/tests/browser_stream.cjs',env=env)
   assert await process.wait()==0,'MSE browser did not render genuine frames'
  finally:server.should_exit=True;await serving
asyncio.run(main())
