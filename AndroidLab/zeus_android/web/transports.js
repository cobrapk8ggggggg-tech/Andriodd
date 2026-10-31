"use strict";
(() => {
  function connect({token,channel,after=0,onEvent,onBytes,onClose,baseURL=location.href}) {
    const url=new URL('/v1/stream',baseURL);url.protocol=url.protocol==='https:'?'wss:':'ws:';
    const socket=new WebSocket(url);socket.binaryType='arraybuffer';let intentional=false;
    socket.onopen=()=>socket.send(JSON.stringify({token,channel,after}));
    socket.onmessage=event=>{if(typeof event.data==='string'){try{onEvent?.(JSON.parse(event.data));}catch(e){onClose?.(e);}}else onBytes?.(event.data);};
    socket.onclose=()=>{if(!intentional)onClose?.(new Error('انقطع اتصال المختبر؛ يمكن إعادة الاتصال خلال الجلسة.'));};
    return {abort(){intentional=true;socket.close();},socket};
  }
  function player({token,video,image,onState,onError,baseURL=location.href}) {
    let channel,media,url,buffer,queue=[],queued=0,closed=false,fallback=false,lastPrune=0,ready,decoded=false,startup,displaying=false;
    function reset(){clearTimeout(startup);channel?.abort();channel=null;queue=[];queued=0;buffer=null;decoded=false;displaying=false;video.removeEventListener('loadeddata',onDecoded);video.pause();video.removeAttribute('src');video.load();if(url){URL.revokeObjectURL(url);url=null;}}
    function onDecoded(){if(closed||fallback)return;decoded=true;displaying=true;video.hidden=false;image.hidden=true;clearTimeout(startup);onState('فيديو مباشر · H.264 عبر WebSocket');}
    function frames(reason){if(closed||fallback)return;reset();fallback=true;video.hidden=true;image.hidden=false;onState('لقطات متتابعة · '+reason);
      channel=connect({token,baseURL,channel:'frames',onEvent:v=>{if(v.error)onError(new Error(v.error));},onBytes:data=>{if(closed)return;const next=URL.createObjectURL(new Blob([data],{type:'image/jpeg'}));const previous=image.src;image.onload=()=>{displaying=true;video.hidden=true;image.hidden=false;if(previous.startsWith('blob:'))URL.revokeObjectURL(previous);};image.src=next;},onClose:e=>{displaying=false;onError(e);}});
    }
    function pump(){if(closed||fallback||!buffer||buffer.updating)return;
      try{
        const ranges=buffer.buffered;
        if(ranges.length){const end=ranges.end(ranges.length-1),start=ranges.start(ranges.length-1);if(video.currentTime<start||video.currentTime<end-1.2)video.currentTime=Math.max(start,end-.2);
          if(ranges.start(0)<end-8&&Date.now()-lastPrune>3000){lastPrune=Date.now();buffer.remove(0,end-5);return;}}
        if(queue.length){const data=queue.shift();queued-=data.byteLength;buffer.appendBuffer(data);video.play().catch(()=>{});}
      }catch(e){frames('تعذر فك الفيديو في هذا المتصفح');}
    }
    const Media=window.ManagedMediaSource||window.MediaSource;
    if(!Media){frames('المتصفح لا يدعم MSE');return {get isDisplaying(){return displaying;},close(){closed=true;reset();image.hidden=true;}};}
    media=new Media();video.disableRemotePlayback=true;video.hidden=false;image.hidden=true;url=URL.createObjectURL(media);
    video.addEventListener('loadeddata',onDecoded,{once:true});startup=setTimeout(()=>{if(!decoded)frames('لم يصل إطار فيديو قابل للعرض');},15000);
    ready=new Promise(resolve=>media.addEventListener('sourceopen',resolve,{once:true}));video.src=url;video.play().catch(()=>{});
    channel=connect({token,baseURL,channel:'video',onEvent:async value=>{
      if(value.error){frames('تعذر نقل H.264');return;}
      if(!value.mime)return;
      if(!Media.isTypeSupported(value.mime)){frames('ترميز الفيديو غير مدعوم');return;}
      try{await ready;if(closed||fallback)return;buffer=media.addSourceBuffer(value.mime);buffer.addEventListener('updateend',pump);buffer.addEventListener('error',()=>frames('تعذر قراءة أجزاء الفيديو'));onState('يجري تهيئة فيديو H.264…');pump();}catch(e){frames('تعذر تهيئة مشغل الفيديو');}
    },onBytes:data=>{if(closed||fallback)return;queued+=data.byteLength;if(queued>2*1024*1024){frames('الاتصال أبطأ من بث الفيديو');return;}queue.push(data);pump();},onClose:e=>{if(!closed&&!fallback)frames('انقطع مسار الفيديو');else if(!closed)onError(e);}});
    return {get isDisplaying(){return displaying;},close(){closed=true;reset();const previous=image.src;image.removeAttribute('src');image.hidden=true;if(previous.startsWith('blob:'))URL.revokeObjectURL(previous);}};
  }
  window.ZeusLabTransport={connect,player};
})();
