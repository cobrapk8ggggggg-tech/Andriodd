const fs=require('node:fs'),crypto=require('node:crypto');

class PrivateArchive {
 constructor(repository,token,launch,fetcher=fetch){this.repository=repository;this.token=token;this.launch=launch;this.fetch=fetcher;this.release=null;}
 async api(path,options={}){
  const response=await this.fetch('https://api.github.com/repos/'+this.repository+path,{...options,headers:{Authorization:'Bearer '+this.token,Accept:'application/vnd.github+json','User-Agent':'ZEUS-Android-Lab',...options.headers},redirect:'error',signal:AbortSignal.timeout(30000)});
  if(!response.ok)throw Error('Private archive API HTTP '+response.status);
  return response.json();
 }
 async initialize(){
  const repository=await this.api('');if(repository.private!==true)throw Error('Durable unsealed lab archives require a private repository');
  let id=this.launch.release_id;
  if(!id&&this.launch.fixture_only&&this.launch.verify_archives){
   const created=await this.api('/releases',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tag_name:'zeus-lab-'+this.launch.session,target_commitish:process.env.GITHUB_SHA,draft:true,name:'ZEUS controlled archive verification'})});id=created.id;
  }
  if(!Number.isSafeInteger(id)||id<=0)throw Error('The session has no valid private draft release');
  const release=await this.api('/releases/'+id);
  if(release.tag_name!=='zeus-lab-'+this.launch.session||release.draft!==true)throw Error('Private archive release does not match this session');
  this.release=id;return id;
 }
 async upload(file,name){
  if(!this.release)throw Error('Private archive was not initialized');
  const size=fs.statSync(file).size;if(size<=0||size>1024**3)throw Error('Private archive asset exceeds 1 GiB');
  const hash=crypto.createHash('sha256');for await(const block of fs.createReadStream(file))hash.update(block);const digest='sha256:'+hash.digest('hex');
  const existing=await this.api('/releases/'+this.release+'/assets?per_page=100');
  const previous=existing.find(a=>a.name===name);
  if(previous){if(previous.size===size&&previous.digest===digest&&previous.state==='uploaded')return previous;throw Error('An archive name already exists with unverified contents');}
  const response=await this.fetch('https://uploads.github.com/repos/'+this.repository+'/releases/'+this.release+'/assets?name='+encodeURIComponent(name),{
   method:'POST',headers:{Authorization:'Bearer '+this.token,'User-Agent':'ZEUS-Android-Lab','Content-Type':'application/octet-stream','Content-Length':String(size)},body:fs.createReadStream(file),duplex:'half',redirect:'error',signal:AbortSignal.timeout(600000)});
  if(response.status!==201)throw Error('Private archive upload HTTP '+response.status);
  const result=await response.json();
  if(result.size!==size||result.name!==name||result.state!=='uploaded'||result.digest&&result.digest!==digest)throw Error('Private archive upload could not be verified');
  return {...result,verified_sha256:digest.slice(7)};
 }
}
module.exports={PrivateArchive};
