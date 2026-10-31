const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',args:['--no-sandbox']});
 try{
  const page=await browser.newPage({viewport:{width:1024,height:900},hasTouch:true});const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(process.env.LAB_STREAM_URL+'#token='+process.env.LAB_TEST_TOKEN);
  try {await page.waitForFunction(()=>{const v=document.getElementById('video');return v.readyState>=2&&v.videoWidth>0&&v.currentTime>0;},null,{timeout:25000});}catch(e){console.log('TRANSPORT_DIAGNOSTIC',await page.evaluate(()=>({state:document.getElementById('transportState').textContent,issue:document.getElementById('error').textContent,video:{ready:document.getElementById('video').readyState,error:document.getElementById('video').error?.message},hasMSE:!!window.MediaSource})),errors);throw e;}
  const value=await page.locator('video').evaluate(v=>({width:v.videoWidth,height:v.videoHeight,time:v.currentTime,decoded:v.getVideoPlaybackQuality().totalVideoFrames}));
  assert.equal(value.width,64);assert.equal(value.height,96);assert(value.decoded>0);assert((await page.locator('#transportState').textContent()).includes('H.264'));assert.equal(errors.length,0,errors.join('\n'));
  if(process.env.LAB_PROOF_DIR){fs.mkdirSync(process.env.LAB_PROOF_DIR,{recursive:true});await page.screenshot({path:process.env.LAB_PROOF_DIR+'/synthetic-fmp4-transport.png'});fs.writeFileSync(process.env.LAB_PROOF_DIR+'/synthetic-fmp4-transport.json',JSON.stringify(value,null,2));}
  console.log('PASS: real Chromium MSE decoded H.264/fMP4 over authenticated WebSocket from synthetic source',JSON.stringify(value));
  await page.close();
  const native=await browser.newPage({viewport:{width:1024,height:900},hasTouch:true});
  await native.addInitScript(({token})=>{
   window.zeusLabNative=async(path,body)=>{
    if(path==='/v1/transport')return {preferred:'github_frames',network_feed:'github_poll'};
    if(path==='/v1/heartbeat')return {};
    const response=await fetch(path,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
    const value=await response.json();if(!response.ok)throw Error(value.detail||'Native protocol fixture failed');return value;
   };
  },{token:process.env.LAB_TEST_TOKEN});
  await native.goto(process.env.LAB_STREAM_URL);
  await native.waitForFunction(()=>document.getElementById('transportState').textContent.includes('GitHub'));
  await native.evaluate(({token,url})=>window.zeusLabDirectStream({preferred:'websocket',network_feed:'github_poll',stream_token:token,stream_url:url}),{token:process.env.LAB_TEST_TOKEN,url:process.env.LAB_STREAM_URL});
  await native.waitForFunction(()=>{const v=document.getElementById('video');return !v.hidden&&v.videoWidth===64&&v.currentTime>0;},null,{timeout:15000});
  await native.evaluate(()=>window.dispatchEvent(new CustomEvent('zeusLabFrame',{detail:{observed_at:Date.now()/1000,screenshot:'old-github-screenshot',network:{events:[]}}})));
  assert.equal(await native.locator('#video').evaluate(v=>v.hidden),false,'A stale GitHub fallback frame must not hide decoded live video');
  await native.evaluate(()=>window.zeusLabDirectStream({preferred:'github_frames',network_feed:'github_poll'}));
  await native.waitForFunction(()=>document.getElementById('video').hidden);
  console.log('PASS native bridge protocol: GitHub fallback → authenticated direct video → fallback; stale frames do not replace decoded video');
  await native.close();
 }finally{await browser.close();}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
