const fs=require('node:fs');
const path=require('node:path');
const {spawn}=require('node:child_process');
const {DefaultArtifactClient}=require('@actions/artifact');
const proof=path.resolve(process.env.CHATGPT_PROOF_DIR);
const client=new DefaultArtifactClient();
let exit=null;const child=spawn('python',['-u','experiments/chatgpt-trial/controller.py'],{stdio:'inherit',env:process.env});
child.on('exit',code=>{exit=code===null?1:code;});
child.on('error',e=>{console.error(e.message);exit=1;});
const published=new Set();
function files(dir){return fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>e.isDirectory()?files(path.join(dir,e.name)):[path.join(dir,e.name)]);}
(async()=>{
 while(true){
  for(const name of fs.readdirSync(proof).filter(n=>/^ready-\d+\.json$/.test(n)).sort()){
   if(published.has(name))continue;
   const value=JSON.parse(fs.readFileSync(path.join(proof,name),'utf8'));
   const root=path.resolve(proof,value.directory);
   if(!root.startsWith(proof+path.sep))throw Error('Invalid observation directory');
   const artifact=await client.uploadArtifact(`chatgpt-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}-${value.sequence}`,files(root),root,{retentionDays:2,compressionLevel:6});
   console.log(`OBSERVATION_PUBLISHED sequence=${value.sequence} artifact=${artifact.id}`);published.add(name);
  }
  if(exit!==null&&fs.readdirSync(proof).filter(n=>/^ready-\d+\.json$/.test(n)).every(n=>published.has(n)))break;
  await new Promise(r=>setTimeout(r,1000));
 }
 if(exit!==0)process.exitCode=exit;
})().catch(e=>{console.error(e.message);child.kill('SIGTERM');process.exitCode=1;});
