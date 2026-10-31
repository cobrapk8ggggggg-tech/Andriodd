const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const {PrivateArchive}=require('./github_archive.cjs');
const directory=fs.mkdtempSync(path.join(os.tmpdir(),'zeus-storage-proof-'));
const launch={session:crypto.randomUUID(),fixture_only:true,verify_archives:true};
const storage=new PrivateArchive(process.env.GITHUB_REPOSITORY,process.env.GITHUB_TOKEN,launch);
function python(operation){
 const result=spawnSync('python',['AndroidLab/actions/verify_storage.py',operation,directory],{encoding:'utf8',env:{PATH:process.env.PATH,HOME:directory,LANG:'C.UTF-8',PYTHONPATH:'AndroidLab'}});
 if(result.status!==0)throw Error('Storage proof '+operation+' failed: '+result.stderr.slice(-1500));return result.stdout;
}
async function signed(asset,digest){
 const response=await fetch('https://api.github.com/repos/'+storage.repository+'/releases/assets/'+asset.id,{headers:{Authorization:'Bearer '+storage.token,Accept:'application/octet-stream'},redirect:'manual',signal:AbortSignal.timeout(20000)});
 const url=response.headers.get('location');if(response.status!==302||!url)throw Error('Private asset did not issue an expiring download');
 fs.writeFileSync(path.join(directory,'transfer.json'),JSON.stringify({url,sha256:digest}),{mode:0o600});
}
(async()=>{
 try{
  await storage.initialize();python('prepare');const input=JSON.parse(fs.readFileSync(path.join(directory,'input.json')));
  const apk=await storage.upload(path.join(directory,'original.apk'),'controlled-storage-fixture.apk');await signed(apk,input.sha256);python('import');
  const metadata=JSON.parse(fs.readFileSync(path.join(directory,'checkpoint.json')));
  const archive=await storage.upload(path.join(directory,'checkpoint.tar.gz'),'checkpoint-000099.tar.gz');await signed(archive,metadata.sha256);
  const result=JSON.parse(python('restore'));if(!result.passed||!result.archive_exceeds_former_25MiB_limit)throw Error('Incomplete archive verification');
  console.log('PASS actual private GitHub upload → expiring download → APK import → snapshot → private upload → project restore');
  fs.writeFileSync(process.env.RUNNER_TEMP+'/zeus-storage-proof.json',JSON.stringify({...result,release:storage.release,fixture_release_removed_after_test:true},null,2));
 }finally{
  if(storage.release){const response=await fetch('https://api.github.com/repos/'+storage.repository+'/releases/'+storage.release,{method:'DELETE',headers:{Authorization:'Bearer '+storage.token},redirect:'error',signal:AbortSignal.timeout(20000)});if(response.status!==204)throw Error('The controlled storage fixture release needs cleanup');}
  fs.rmSync(directory,{recursive:true,force:true});
 }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
