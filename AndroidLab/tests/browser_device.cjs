const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const path=require('node:path');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH||'/usr/bin/google-chrome',
  args:['--no-sandbox','--disable-features=WebRtcHideLocalIpsWithMdns']});
 try{
  const page=await browser.newPage({viewport:{width:390,height:844},isMobile:true,hasTouch:true});
  await page.goto('http://127.0.0.1:8088/lab/#token='+process.env.LAB_TEST_TOKEN);
  await page.waitForFunction(()=>{const v=document.getElementById('video');return v&&v.readyState>=2&&v.videoWidth>0&&v.currentTime>0;},null,{timeout:35000});
  const size=await page.locator('video').evaluate(v=>[v.videoWidth,v.videoHeight]);assert(size[0]>0&&size[1]>0);
  await page.waitForFunction(()=>Number(document.getElementById('count').textContent)>=1,{},{timeout:10000});
  await page.locator('[data-tab="network"]').click();
  await page.locator('#filter').fill('/probe');
  assert.equal(await page.locator('#flows button').count(),1,'Request phases must update one row');
  await page.locator('#flows button').first().click();
  await page.waitForFunction(()=>document.getElementById('flowContent').textContent.includes('مرحبا ZEUS probe'));
  await page.screenshot({path:path.join(process.env.LAB_PROOF_DIR,'actual-browser-https-capture.png'),fullPage:true});
  await page.locator('#closeDetail').click();await page.locator('[data-tab="device"]').click();
  await page.screenshot({path:path.join(process.env.LAB_PROOF_DIR,'actual-browser-android-video.png'),fullPage:true});
  await page.locator('#fullscreen').click();await page.screenshot({path:path.join(process.env.LAB_PROOF_DIR,'actual-browser-android-fullscreen.png')});
  await page.close();console.log('PASS: actual Android WebRTC video rendered inside the ZEUS browser UI');
 }finally{await browser.close();}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
