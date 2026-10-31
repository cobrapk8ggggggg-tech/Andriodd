// Protocol tests use a fake HTTP transport; the real private API has a separate CI gate.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {PrivateArchive}=require('../actions/github_archive.cjs');
const launch={session:'controlled-session',release_id:42};
const json=value=>new Response(JSON.stringify(value),{status:200,headers:{'Content-Type':'application/json'}});
test('private repository and exact session draft are checked before any upload',async()=>{
 for(const bad of ['public','tag','published']){
  let writes=0;
  const storage=new PrivateArchive('owner/repository','private-account-token',launch,async(url,options)=>{
   if(options.method==='POST')writes++;
   if(url.endsWith('/releases/42'))return json({tag_name:bad==='tag'?'another-session':'zeus-lab-controlled-session',draft:bad!=='published'});
   return json({private:bad!=='public'});
  });
  await assert.rejects(storage.initialize());assert.equal(writes,0);
 }
});
test('streamed private upload is verified and a mismatched retry never overwrites',async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'lab-archive-')),file=path.join(directory,'checkpoint.tar.gz');fs.writeFileSync(file,'controlled archive');
 const digest='sha256:'+crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');let previous=[],writes=0;
 const storage=new PrivateArchive('owner/repository','private-account-token',launch,async(url,options)=>{
  assert.equal(options.headers.Authorization,'Bearer private-account-token');
  if(url.startsWith('https://uploads.github.com/')){writes++;let bytes=0;for await(const block of options.body)bytes+=block.length;assert.equal(bytes,18);return new Response(JSON.stringify({id:7,size:18,name:'checkpoint.tar.gz',state:'uploaded',digest}),{status:201});}
  if(url.includes('/assets?'))return json(previous);
  return json(url.endsWith('/releases/42')?{tag_name:'zeus-lab-controlled-session',draft:true}:{private:true});
 });
 try{await storage.initialize();const saved=await storage.upload(file,'checkpoint.tar.gz');assert.equal(saved.verified_sha256,digest.slice(7));
  previous=[{...saved,digest:'sha256:wrong'}];await assert.rejects(storage.upload(file,'checkpoint.tar.gz'));assert.equal(writes,1);
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});
