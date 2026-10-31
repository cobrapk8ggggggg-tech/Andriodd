const fs=require('node:fs'),path=require('node:path'),{spawn}=require('node:child_process');
const {DefaultArtifactClient}=require('@actions/artifact');
const {PrivateArchive}=require('./github_archive.cjs');
const client=new DefaultArtifactClient(),root=process.env.LAB_ACTIONS_PROOF;
const python=process.env.pythonLocation?path.join(process.env.pythonLocation,'bin/python'):'python';
const child=spawn('sudo',['-n','--preserve-env=LAB_ACTIONS_PROOF,LAB_PROBE_APK,ZEUS_ANDROID_IME_APK,NODE_PATH,CHROMIUM_PATH,ANDROID_HOME,ANDROID_SDK_ROOT,PATH,PYTHONPATH,ZEUS_ANDROID_BUILD_UID,ZEUS_ANDROID_TOOL_NETNS,LAB_CAPTURE_EXE,GITHUB_REPOSITORY,GITHUB_RUN_ID',python,'-u','AndroidLab/actions/session.py'],{stdio:'inherit',env:process.env});
let exit=null;child.on('exit',code=>exit=code??1);child.on('error',()=>exit=1);
const published=new Set();let checkpointBytes=0,etags=new Map(),polling=true;
const control=path.join(path.dirname(root),'zeus-lab-control');fs.mkdirSync(control,{recursive:true,mode:0o700});
async function pollControl(kind='incoming'){
 if(!process.env.GITHUB_TOKEN)return;
 const source=kind==='emergency'?'emergency':'control',etag=etags.get(kind)||'';
 const branch=encodeURIComponent(process.env.GITHUB_REF_NAME),repository=process.env.GITHUB_REPOSITORY;
 const response=await fetch(`https://api.github.com/repos/${repository}/contents/experiments/actions-lab/${source}.json?ref=${branch}`,{headers:{Authorization:'Bearer '+process.env.GITHUB_TOKEN,Accept:'application/vnd.github+json',...(etag?{'If-None-Match':etag}:{})},redirect:'error',signal:AbortSignal.timeout(10000)});
 if(response.status===304||response.status===404)return;if(!response.ok)throw Error('GitHub control channel HTTP '+response.status);
 etags.set(kind,response.headers.get('etag')||'');const value=await response.json();if(value.size>256000)throw Error('Encrypted control exceeds limit');
 const data=Buffer.from(value.content,'base64');if(data.length>256000)throw Error('Encrypted control exceeds limit');
 const temporary=path.join(control,kind+'.tmp');fs.writeFileSync(temporary,data,{mode:0o600});fs.renameSync(temporary,path.join(control,kind+'.json'));
}

function files(dir){return fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>e.isDirectory()?files(path.join(dir,e.name)):[path.join(dir,e.name)]);}
(async()=>{
 const launch=JSON.parse(fs.readFileSync('experiments/actions-lab/launch.json','utf8'));
 let archive=null;
 if(launch.private_archive){archive=new PrivateArchive(process.env.GITHUB_REPOSITORY,process.env.GITHUB_TOKEN,launch);await archive.initialize();}
 const controls=(async()=>{while(polling){if(exit===null){try{await Promise.all([pollControl(),pollControl('emergency')]);}catch(e){console.error(e.message);}}await new Promise(r=>setTimeout(r,3000));}})();
 try{
 while(true){
  for(const name of fs.readdirSync(root).filter(n=>/^ready-\d+\.json$/.test(n)).sort()){
   if(published.has(name))continue;
   const ready=JSON.parse(fs.readFileSync(path.join(root,name),'utf8')),directory=path.resolve(root,ready.directory);
   if(!directory.startsWith(path.resolve(root)+path.sep))throw Error('Invalid checkpoint directory');
   const entries=files(directory),bytes=entries.reduce((n,f)=>n+fs.statSync(f).size,0);
   if(ready.kind==='private_release'){
    if(!archive)throw Error('Durable archive requested without a verified private release');
    if(entries.length!==2||!entries.some(f=>path.basename(f)==='manifest.json')||!entries.some(f=>/^checkpoint-\d{6}\.tar\.gz$/.test(path.basename(f))))throw Error('Invalid private archive contents');
    const assets=[];
    for(const file of entries)assets.push(await archive.upload(file,path.basename(file)==='manifest.json'?`checkpoint-${String(ready.sequence).padStart(6,'0')}.json`:path.basename(file)));
    console.log(`LAB_PRIVATE_ARCHIVE sequence=${ready.sequence} release=${archive.release} assets=${assets.map(a=>a.id).join(',')} bytes=${bytes}`);published.add(name);continue;
   }
   if(checkpointBytes+bytes>50*1024*1024)throw Error('Test artifact budget reached; session data remains on runner until cleanup');
   if(entries.some(f=>!f.endsWith('.sealed.json')&&!f.endsWith('.zlab')&&!f.endsWith('public-status.json')))throw Error('Refusing an unencrypted Actions artifact');
   const artifact=await client.uploadArtifact(`zeus-lab-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}-${ready.sequence}`,entries,directory,{retentionDays:1,compressionLevel:0});
   checkpointBytes+=bytes;console.log(`LAB_ENCRYPTED_CHECKPOINT sequence=${ready.sequence} artifact=${artifact.id} bytes=${bytes}`);published.add(name);
  }
  if(exit!==null&&fs.readdirSync(root).filter(n=>/^ready-\d+\.json$/.test(n)).every(n=>published.has(n)))break;
  await new Promise(r=>setTimeout(r,1000));
 }
 process.exitCode=exit;
 }finally{polling=false;await controls;}
})().catch(e=>{polling=false;console.error(e.message);child.kill('SIGTERM');process.exitCode=1;});
