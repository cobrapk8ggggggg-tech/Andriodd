const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH || '/usr/bin/chromium',args:['--no-sandbox']});
 try{
  for(const [name,width,height] of [['iphone',390,844],['ipad',1024,1366]]){
   const context=await browser.newContext({viewport:{width,height},isMobile:true,hasTouch:true});const page=await context.newPage();
   const errors=[];page.on('pageerror',e=>errors.push(e.message));
   await page.goto('http://127.0.0.1:8769/lab/#token='+process.env.LAB_TEST_TOKEN);await page.getByText('التحكم لك',{exact:true}).waitFor();
   assert(!page.url().includes('token='));assert.equal(await page.locator('video').count(),1);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   await page.getByRole('button',{name:/الشبكة/}).click();await page.getByRole('heading',{name:'حركة الشبكة'}).waitFor({state:'visible'});
   await page.locator('#flows button').filter({hasText:'https://saved.invalid/past'}).click();
   await page.waitForFunction(()=>document.getElementById('flowContent').textContent.includes('saved log'));
   await page.locator('#closeDetail').click();
   await page.getByRole('button',{name:'المشروع',exact:true}).click();await page.getByRole('heading',{name:'التطبيق والمشروع'}).waitFor({state:'visible'});
   const filename='fixture-'+name+'.apk';
   await page.locator('#apk').setInputFiles({name:filename,mimeType:'application/vnd.android.package-archive',buffer:fs.readFileSync(process.env.LAB_TEST_APK)});
   await page.locator('#projects').getByText(filename,{exact:true}).waitFor();assert.equal(errors.length,0,errors.join('\n'));
   await page.getByRole('button',{name:'الأحداث',exact:true}).click();await page.getByRole('heading',{name:'سجل الأحداث'}).waitFor();
   await page.getByRole('button',{name:'التحليل والتقارير',exact:true}).click();await page.getByRole('heading',{name:'تحليل التطبيق',exact:true}).waitFor();
   assert.equal(await page.locator('#analysisSummary .metric').count(),0,'No fake audit results before an actual audit');
   await page.getByRole('button',{name:'المشروع',exact:true}).click();
   await page.screenshot({path:path.join(process.env.LAB_PROOF_DIR,name+'-project.png'),fullPage:true});
   await page.getByRole('button',{name:'الجهاز',exact:true}).click();await page.screenshot({path:path.join(process.env.LAB_PROOF_DIR,name+'-device.png'),fullPage:true});
   await page.locator('#fullscreen').click();assert(await page.locator('body').evaluate(x=>x.classList.contains('device-fullscreen')));
   assert((await page.locator('#screen').boundingBox()).height>height*.75);
   await page.screenshot({path:path.join(process.env.LAB_PROOF_DIR,name+'-fullscreen.png')});await page.locator('#fullscreen').click();
   await context.close();console.log(name+': layout, navigation, token removal and direct APK upload passed');
  }
 }finally{await browser.close();}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
