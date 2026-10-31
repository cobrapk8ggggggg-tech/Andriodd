const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),{randomUUID}=require('node:crypto');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH||'/usr/bin/google-chrome',args:['--no-sandbox','--disable-dev-shm-usage']});
 let page;const proof=process.env.LAB_PROOF_DIR;
 try{
  page=await browser.newPage({viewport:{width:1024,height:900},hasTouch:true});const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(process.env.LAB_LIVE_URL+'#token='+process.env.LAB_LIVE_TOKEN,{waitUntil:'domcontentloaded',timeout:45000});
  await page.waitForFunction(()=>{const v=document.getElementById('video'),i=document.getElementById('screenImage');return v.readyState>=2&&v.videoWidth>0&&v.currentTime>0||!i.hidden&&i.naturalWidth>0;},null,{timeout:45000});
  assert.equal(new URL(page.url()).hostname.endsWith('.trycloudflare.com'),true);
  const mode=await page.locator('#video').evaluate(v=>v.hidden?'frames':'fmp4');
  async function pixels(){return page.evaluate(()=>{const source=document.getElementById('video').hidden?document.getElementById('screenImage'):document.getElementById('video');const c=document.createElement('canvas');c.width=c.height=24;const ctx=c.getContext('2d');ctx.drawImage(source,0,0,24,24);return Array.from(ctx.getImageData(0,0,24,24).data).reduce((n,v,i)=>(n+v*(i+1))%2147483647,0);});}
  async function tree(){const response=await page.request.post(new URL('/v1/tool',process.env.LAB_LIVE_URL).href,{headers:{Authorization:'Bearer '+process.env.LAB_LIVE_TOKEN},data:{name:'android_ui',arguments:{operation:'tree'},request_id:randomUUID()}});assert.equal(response.status(),200);return response.json();}
  const before=await tree();assert(before.nodes.some(n=>n['content-desc']==='probeInput'),'Expected actual installed repository probe');
  const beforePixels=await pixels();await page.screenshot({path:path.join(proof,'actual-tunnel-probe.png'),fullPage:true});
  await page.locator('[data-key="home"]').click();
  await page.waitForTimeout(2500);const after=await tree();assert(!after.nodes.some(n=>n['content-desc']==='probeInput'),'Home must change the actual Android UI');
  let afterPixels=await pixels();for(let i=0;i<10&&afterPixels===beforePixels;i++){await page.waitForTimeout(500);afterPixels=await pixels();}
  assert.notEqual(afterPixels,beforePixels,'The visible frame must change after actual ADB input through HTTPS');
  await page.screenshot({path:path.join(proof,'actual-tunnel-home.png'),fullPage:true});
  assert.equal(errors.length,0,errors.join('\n'));
  const video=await page.locator('#video').evaluate(v=>({width:v.videoWidth,height:v.videoHeight,time:v.currentTime,decoded:v.getVideoPlaybackQuality?.().totalVideoFrames}));
  fs.writeFileSync(path.join(proof,'tunnel-acceptance.json'),JSON.stringify({passed:true,source:'actual Android AVD32',origin:new URL(page.url()).origin,mode,video,actual_adb_home_changed_ui:true,visible_pixels_changed:true,transport:'authenticated WebSocket via Cloudflare temporary HTTPS relay',physical_ipad_tested:false},null,2));
  console.log('PASS actual temporary HTTPS relay, actual Android display, ADB touch control, changed device UI and displayed pixels');
 }catch(error){
  if(page){try{await page.screenshot({path:path.join(proof,'tunnel-failure.png'),fullPage:true});console.error('DIAGNOSTIC',await page.evaluate(()=>({state:document.getElementById('transportState')?.textContent,issue:document.getElementById('error')?.textContent,ready:document.getElementById('video')?.readyState,mediaError:document.getElementById('video')?.error?.message})));}catch{}}
  throw error;
 }finally{await browser.close();}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
