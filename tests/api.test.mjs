import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
const folder=mkdtempSync(join(tmpdir(),'fx-test-'));
const dbPath=join(folder,'test.sqlite');
const password='Local-test-password-2026';
const port=Number(process.env.FX_TEST_PORT || 3107);
const base=`http://127.0.0.1:${port}`;
let child,admin,lister,shipper,createdId;
async function start(path=dbPath) {
 child=spawn(process.execPath,['server/index.mjs'],{env:{...process.env,PORT:String(port),FX_DB:path,FX_DEMO_PASSWORD:password},stdio:['ignore','pipe','pipe']});
 let output='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);
 for(let i=0;i<80;i++){if(child.exitCode!==null)throw new Error(output);try{const r=await fetch(`${base}/api/me`);if(r.status===401)return;}catch{}await new Promise(r=>setTimeout(r,50));}
 throw new Error('Server not ready: '+output);
}
async function stop(){if(child?.exitCode===null)await new Promise(resolve=>{child.once('exit',resolve);child.kill('SIGTERM');});}
async function request(path,{cookie,method='GET',body,key,headers={}}={}) {
 const r=await fetch(base+'/api'+path,{method,headers:{'Content-Type':'application/json','X-FX-Request':'1',...(cookie?{Cookie:cookie}:{}),...(key?{'Idempotency-Key':key}:{}),...headers},...(body!==undefined?{body:JSON.stringify(body)}:{})});
 const text=await r.text();let data;try{data=JSON.parse(text);}catch{data=text;}return {status:r.status,data,headers:r.headers};
}
async function login(email,pw=password){const r=await request('/login',{method:'POST',body:{email,password:pw}});assert.equal(r.status,200,JSON.stringify(r.data));return r.headers.get('set-cookie').split(';')[0];}
const payload=(extra={})=>({title:'Test leather bag',ebay_id:'987654321000',price:'12.34',quantity:2,location:'Test shelf',owner_id:2,note:'Test note',...extra});
before(async()=>{await start();admin=await login('Admin','Welcome!');assert.equal((await request('/items',{cookie:admin})).status,403);const changed=await request('/password',{cookie:admin,method:'POST',body:{currentPassword:'Welcome!',newPassword:'Admin-local-password-2026',confirmPassword:'Admin-local-password-2026'}});assert.equal(changed.status,200,JSON.stringify(changed.data));lister=await login('arseniy@fashionexchange.local');shipper=await login('shipping@fashionexchange.local');});
after(async()=>{await stop();rmSync(folder,{recursive:true,force:true});});

test('unauthenticated requests and foreign-origin writes are rejected',async()=>{
 assert.equal((await request('/items')).status,401);
 assert.equal((await request('/items',{cookie:admin,method:'POST',headers:{Origin:'https://evil.example'},body:payload(),key:randomUUID()})).status,403);
 const hostStatus=await new Promise((resolve,reject)=>{const req=httpRequest(`${base}/api/items`,{headers:{Host:'evil.example',Cookie:admin}},res=>{res.resume();resolve(res.statusCode);});req.on('error',reject);req.end();});
 assert.equal(hostStatus,403);
 const bad=await request('/login',{method:'POST',body:{email:'missing@example.com',password:'wrong'}});assert.equal(bad.status,401);assert.equal(bad.data.error,'Incorrect email or password.');
});
test('save is idempotent, exact cents persist, eBay IDs are unique',async()=>{
 const key=randomUUID();const [a,b]=await Promise.all([request('/items',{cookie:lister,method:'POST',body:payload(),key}),request('/items',{cookie:lister,method:'POST',body:payload(),key})]);
 assert.equal(a.status,201,JSON.stringify(a.data));assert.equal(b.status,201);assert.equal(a.data.id,b.data.id);assert.equal(a.data.price_cents,1234);createdId=a.data.id;
 const duplicate=await request('/items',{cookie:admin,method:'POST',body:payload(),key:randomUUID()});assert.equal(duplicate.status,409,JSON.stringify(duplicate.data));assert.match(duplicate.data.error,/already saved/);
 assert.equal((await request('/items',{cookie:lister,method:'POST',body:payload({title:'Different'}),key})).status,409);
});
test('server validates quantities, price precision, and owner permissions',async()=>{
 for(const extra of [{quantity:-1},{quantity:1.5},{price:'1.001'},{price:'-1'},{title:''}])assert.equal((await request('/items',{cookie:lister,method:'POST',body:payload(extra),key:randomUUID()})).status,400);
 assert.equal((await request('/items',{cookie:lister,method:'POST',body:payload({owner_id:1}),key:randomUUID()})).status,403);
});
test('shipper can read inventory but cannot modify it, export, or administer users',async()=>{
 assert.equal((await request('/items',{cookie:shipper})).status,200);
 assert.equal((await request('/items/1',{cookie:shipper})).status,200);
 for(const path of ['/items/export','/team','/users'])assert.equal((await request(path,{cookie:shipper})).status,403);
 assert.equal((await request('/items',{cookie:shipper,method:'POST',body:payload(),key:randomUUID()})).status,403);
 assert.equal((await request('/items/2/claim',{cookie:shipper,method:'POST'})).status,403);
 assert.equal((await request('/team',{cookie:lister})).status,403);
 assert.equal((await request('/team',{cookie:lister,method:'POST',body:{name:'No',email:'no@example.com',password:'Long-password-1',role:'admin'}})).status,403);
 assert.equal((await request('/shipments',{cookie:lister})).status,403);
});
test('administrator can create a user with a role and the new login works',async()=>{
 const body={name:'Maria Lopez',email:'Maria@Example.com',password:'Maria-password-2026',role:'lister'};
 const created=await request('/team',{cookie:admin,method:'POST',body});assert.equal(created.status,201,JSON.stringify(created.data));assert.equal(created.data.email,'maria@example.com');assert.equal(created.data.role,'lister');assert.equal(created.data.password_hash,undefined);
 assert.equal((await request('/team',{cookie:admin,method:'POST',body})).status,409);
 const maria=await login('maria@example.com','Maria-password-2026');const profile=(await request('/me',{cookie:maria})).data.user;assert.equal(profile.role,'lister');assert.equal(profile.must_change_password,true);assert.ok(profile.last_login_at);assert.equal((await request('/items',{cookie:maria})).status,403);
 const changed=await request('/password',{cookie:maria,method:'POST',body:{currentPassword:'Maria-password-2026',newPassword:'Maria-new-password-2026',confirmPassword:'Maria-new-password-2026'}});assert.equal(changed.status,200);assert.equal(changed.data.user.must_change_password,false);
});
test('admin password reset forces a change and suspension immediately revokes sessions',async()=>{
 const created=await request('/team',{cookie:admin,method:'POST',body:{name:'Temporary User',email:'temp-user',password:'Temporary-password-2026',role:'shipper'}});assert.equal(created.status,201);
 let temp=await login('temp-user','Temporary-password-2026');
 assert.equal((await request(`/team/${created.data.id}/reset-password`,{cookie:admin,method:'POST',body:{password:'Reset-password-2026',confirmPassword:'Reset-password-2026'}})).status,200);
 assert.equal((await request('/me',{cookie:temp})).status,401);
 temp=await login('temp-user','Reset-password-2026');
 assert.equal((await request(`/team/${created.data.id}/status`,{cookie:admin,method:'PATCH',body:{active:false}})).status,200);
 assert.equal((await request('/me',{cookie:temp})).status,401);
 assert.equal((await request('/login',{method:'POST',body:{email:'temp-user',password:'Reset-password-2026'}})).status,401);
 assert.equal((await request(`/team/${created.data.id}/status`,{cookie:admin,method:'PATCH',body:{active:true}})).status,200);
 assert.equal((await request(`/team/1/status`,{cookie:admin,method:'PATCH',body:{active:false}})).status,409);
});
test('lister cannot edit or archive another owner; lost updates are prevented',async()=>{
 const other=await request('/items/6',{cookie:admin});
 assert.equal((await request('/items/6',{cookie:lister,method:'PATCH',body:payload({version:other.data.version})})).status,403);
 assert.equal((await request('/items/6/archive',{cookie:lister,method:'POST',body:{version:other.data.version,archived:true}})).status,403);
 const mine=(await request(`/items/${createdId}`,{cookie:lister})).data;
 const edited=await request(`/items/${createdId}`,{cookie:lister,method:'PATCH',body:payload({title:'Updated bag',price:'19.99',version:mine.version})});
 assert.equal(edited.status,200);assert.equal(edited.data.price_cents,1999);
 assert.equal((await request(`/items/${createdId}`,{cookie:lister,method:'PATCH',body:payload({version:mine.version})})).status,409);
});
test('atomic claim allows only one owner under concurrent requests',async()=>{
 const results=await Promise.all([request('/items/2/claim',{cookie:lister,method:'POST'}),request('/items/2/claim',{cookie:admin,method:'POST'})]);
 assert.deepEqual(results.map(r=>r.status).sort(),[200,409]);
 const item=(await request('/items/2',{cookie:admin})).data;assert.ok([1,2].includes(item.owner_id));
});
test('search, mine filter, archival, restore, and CSV escaping work',async()=>{
 const found=await request('/items?q=Updated%20bag',{cookie:lister});assert.equal(found.status,200,JSON.stringify(found.data));assert.equal(found.data.length,1);
 const byId=await request(`/items?q=FX-${String(createdId).padStart(5,'0')}`,{cookie:admin});assert.equal(byId.data.length,1);
 assert.ok((await request('/items?owner=mine',{cookie:lister})).data.every(i=>i.owner_id===2));
 const item=found.data[0];let archived=await request(`/items/${item.id}/archive`,{cookie:lister,method:'POST',body:{version:item.version,archived:true}});assert.equal(archived.status,200);
 assert.equal((await request('/items?archived=true',{cookie:admin})).data.length,1);
 assert.equal((await request(`/items/${item.id}/archive`,{cookie:lister,method:'POST',body:{version:archived.data.version,archived:false}})).status,200);
 const dangerous=await request('/items',{cookie:admin,method:'POST',body:payload({title:'=SUM(1,2)',ebay_id:null,note:'"quoted", note'}),key:randomUUID()});assert.equal(dangerous.status,201);
 const csv=await request('/items/export',{cookie:admin});assert.equal(csv.status,200);assert.match(csv.data,/'=SUM/);assert.match(csv.data,/""quoted""/);
});
test('shipment transitions persist actor and reject repeat actions',async()=>{
 let s=(await request('/shipments',{cookie:shipper})).data[0];
 assert.equal((await request(`/items/1/archive`,{cookie:admin,method:'POST',body:{archived:true,version:1}})).status,409);
 assert.equal((await request(`/shipments/${s.id}/advance`,{cookie:shipper,method:'POST',body:{version:s.version}})).status,200);
 assert.equal((await request(`/shipments/${s.id}/advance`,{cookie:shipper,method:'POST',body:{version:s.version}})).status,409);
 s=(await request('/shipments',{cookie:shipper})).data[0];assert.equal(s.status,'packed');assert.equal(s.packed_name,'Sam');
 assert.equal((await request(`/shipments/${s.id}/advance`,{cookie:shipper,method:'POST',body:{version:s.version}})).status,400);
 assert.equal((await request(`/shipments/${s.id}/advance`,{cookie:shipper,method:'POST',body:{version:s.version,tracking_number:'?'}})).status,400);
 assert.equal((await request(`/shipments/${s.id}/advance`,{cookie:shipper,method:'POST',body:{version:s.version,tracking_number:'DEMO-TRACK-12345'}})).status,200);
 s=(await request('/shipments',{cookie:admin})).data[0];assert.equal(s.status,'shipped');assert.equal(s.shipped_name,'Sam');assert.equal(s.tracking_number,'DEMO-TRACK-12345');
 assert.ok((await request('/activity',{cookie:admin})).data.some(a=>a.action==='shipped'&&a.actor_name==='Sam'));
});
test('database survives a server restart',async()=>{
 await stop();await start();
 const item=await request(`/items/${createdId}`,{cookie:lister});assert.equal(item.status,200);assert.equal(item.data.title,'Updated bag');assert.equal(item.data.price_cents,1999);
 assert.equal((await request('/shipments',{cookie:admin})).data[0].status,'shipped');
 assert.equal((await request('/shipments',{cookie:admin})).data[0].tracking_number,'DEMO-TRACK-12345');
});
test('password change revokes other sessions and logout revokes current session',async()=>{
 const second=await login('arseniy@fashionexchange.local');
 assert.equal((await request('/password',{cookie:lister,method:'POST',body:{currentPassword:password,newPassword:'New-local-password-2026',confirmPassword:'New-local-password-2026'}})).status,200);
 assert.equal((await request('/me',{cookie:second})).status,401);
 assert.equal((await request('/me',{cookie:lister})).status,200);
 assert.equal((await request('/logout',{cookie:lister,method:'POST'})).status,200);
 assert.equal((await request('/me',{cookie:lister})).status,401);
 lister=await login('arseniy@fashionexchange.local','New-local-password-2026');
});
test('active requests refresh the two-hour cookie and expired idle sessions are rejected',async()=>{
 const cookie=await login('shipping@fashionexchange.local');const token=cookie.slice('fx_session='.length);const hash=createHash('sha256').update(token).digest('hex');const testDb=new DatabaseSync(dbPath);
 const original=testDb.prepare('SELECT expires_at FROM sessions WHERE token_hash=?').get(hash).expires_at;
 const heartbeat=await request('/me',{cookie,headers:{'X-FX-Heartbeat':'1'}});assert.equal(heartbeat.status,200);assert.equal(heartbeat.headers.get('set-cookie'),null);assert.equal(testDb.prepare('SELECT expires_at FROM sessions WHERE token_hash=?').get(hash).expires_at,original);
 const me=await request('/me',{cookie});assert.equal(me.status,200);assert.match(me.headers.get('set-cookie'),/Max-Age=7200/i);
 testDb.prepare('UPDATE sessions SET expires_at=? WHERE token_hash=?').run(Date.now()-1,hash);testDb.close();
 assert.equal((await request('/me',{cookie})).status,401);
});
test('online backup restores into separate DB, validates integrity, and clears sessions',async()=>{
 const backup=join(folder,'backup.sqlite'),restored=join(folder,'restored.sqlite');
 const backupResult=spawnSync(process.execPath,['scripts/database.mjs','backup',backup],{env:{...process.env,FX_DB:dbPath},encoding:'utf8'});assert.equal(backupResult.status,0,backupResult.stderr);assert.ok(existsSync(backup));
 const restore=spawnSync(process.execPath,['scripts/database.mjs','restore',backup,restored],{encoding:'utf8'});assert.equal(restore.status,0,restore.stderr);
 const restoredDB=new DatabaseSync(restored);assert.equal(restoredDB.prepare('SELECT title FROM items WHERE id=?').get(createdId).title,'Updated bag');assert.equal(restoredDB.prepare('SELECT count(*) AS n FROM sessions').get().n,0);assert.equal(restoredDB.prepare('PRAGMA integrity_check').get().integrity_check,'ok');restoredDB.close();
 const overwrite=spawnSync(process.execPath,['scripts/database.mjs','restore',backup,restored],{encoding:'utf8'});assert.equal(overwrite.status,1);
 await stop();await start(restored);const cookie=await login('Admin','Admin-local-password-2026');assert.equal((await request(`/items/${createdId}`,{cookie})).data.title,'Updated bag');
});
