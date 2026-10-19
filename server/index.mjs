import express from 'express';
import { createHash, randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { db, transaction, audit, hashPassword, verifyPassword } from './db.mjs';

const app = express();
const port = Number(process.env.PORT || 3007);
const sessionIdleMs = 120 * 60 * 1000;
const sha = value => createHash('sha256').update(value).digest('hex');
const fail = (status,message) => Object.assign(new Error(message),{status});
const dummyPasswordHash = hashPassword(randomBytes(24).toString('hex'));
app.disable('x-powered-by');
app.use((req,res,next) => {
  res.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Permissions-Policy':'camera=(), microphone=(), geolocation=(), payment=()',
    'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"});
  if(req.path.startsWith('/api')) res.set('Cache-Control','no-store');
  if (!['GET','HEAD','OPTIONS'].includes(req.method)) {
    if(req.get('X-FX-Request') !== '1') return res.status(403).json({error:'Invalid request origin.'});
  }
  next();
});
app.use(express.json({limit:'64kb'}));
const safeUser = user => ({id:user.id,name:user.name,email:user.email,role:user.role,active:Boolean(user.active),must_change_password:Boolean(user.must_change_password),last_login_at:user.last_login_at});
const attempts = new Map();
app.post('/api/login',(req,res) => {
  const {email,password} = req.body || {};
  if(typeof email !== 'string' || typeof password !== 'string' || password.length > 256) throw fail(400,'Enter your email and password.');
  const key = req.ip;
  const prior = attempts.get(key);
  if(prior && prior.until > Date.now() && prior.count >= 20) throw fail(429,'Too many attempts. Try again in 15 minutes.');
  const login=email.trim();
  const user = db.prepare('SELECT * FROM users WHERE lower(email) = lower(?) AND active=1').get(login);
  const passwordValid=verifyPassword(password,user?.password_hash || dummyPasswordHash);
  if(!user || !passwordValid) {
    attempts.set(key,{count:prior?.until > Date.now() ? prior.count+1 : 1,until:prior?.until > Date.now() ? prior.until : Date.now()+900000});
    throw fail(401,'Incorrect email or password.');
  }
  attempts.delete(key);
  const now=Date.now();db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  const token = randomBytes(32).toString('hex');
  transaction(()=>{db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,last_seen_at) VALUES(?,?,?,?)').run(sha(token),user.id,now+sessionIdleMs,now);db.prepare('UPDATE users SET last_login_at=? WHERE id=?').run(new Date(now).toISOString(),user.id);});
  res.cookie('fx_session',token,{httpOnly:true,sameSite:'strict',maxAge:sessionIdleMs,path:'/'});
  res.json({user:safeUser({...user,last_login_at:new Date(now).toISOString()})});
});
app.use('/api',(req,res,next) => {
  const token = (req.headers.cookie || '').split(';').map(s=>s.trim()).find(s=>s.startsWith('fx_session='))?.slice(11);
  const now=Date.now();const sessionHash=token&&sha(token);
  const user = sessionHash && db.prepare('SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires_at>? AND users.active=1').get(sessionHash,now);
  if(!user) return res.status(401).json({error:'Please sign in to continue.'});
  const heartbeat=req.path==='/me' && req.get('X-FX-Heartbeat')==='1';
  if(!heartbeat){
    db.prepare('UPDATE sessions SET expires_at=?,last_seen_at=? WHERE token_hash=?').run(now+sessionIdleMs,now,sessionHash);
    res.cookie('fx_session',token,{httpOnly:true,sameSite:'strict',maxAge:sessionIdleMs,path:'/'});
  }
  req.user = safeUser(user); req.sessionHash = sessionHash;
  if(req.user.must_change_password && !['/me','/logout','/password'].includes(req.path))return res.status(403).json({error:'Change your temporary password before continuing.',code:'PASSWORD_CHANGE_REQUIRED'});
  next();
});
function roles(...allowed) { return (req,res,next) => { if(!allowed.includes(req.user.role)) return res.status(403).json({error:'Your role does not allow this action.'}); next(); }; }
app.get('/api/me',(req,res)=>res.json({user:req.user}));
app.post('/api/logout',(req,res)=>{db.prepare('DELETE FROM sessions WHERE token_hash=?').run(req.sessionHash);res.clearCookie('fx_session',{path:'/'}).json({ok:true});});
app.post('/api/password',(req,res)=>{
  const {currentPassword,newPassword,confirmPassword}=req.body || {};
  if(typeof currentPassword !== 'string' || currentPassword.length>256 || typeof newPassword !== 'string' || newPassword.length<5 || newPassword.length>128) throw fail(400,'Use a new password between 5 and 128 characters.');
  if(confirmPassword!==newPassword)throw fail(400,'New password and confirmation must match.');
  if(currentPassword===newPassword)throw fail(400,'Choose a password different from your current password.');
  const user=db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if(!verifyPassword(currentPassword,user.password_hash)) throw fail(400,'Current password is incorrect.');
  transaction(()=>{db.prepare('UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?').run(hashPassword(newPassword),user.id);db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?').run(user.id,req.sessionHash);audit(user.id,'user',user.id,'password_changed','Password changed; other sessions revoked.');});
  res.json({ok:true,user:safeUser({...user,must_change_password:0})});
});
app.get('/api/users',roles('admin','lister'),(req,res)=>res.json(db.prepare("SELECT id,name,role FROM users WHERE role IN ('admin','lister') AND active=1").all()));
app.get('/api/team',roles('admin'),(req,res)=>res.json(db.prepare("SELECT id,name,email,role,active,must_change_password,last_login_at FROM users ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'lister' THEN 2 ELSE 3 END,name").all().map(safeUser)));
app.post('/api/team',roles('admin'),(req,res)=>{
  const {name,email,password,role}=req.body || {};
  const cleanName=typeof name==='string'?name.trim():'';
  const cleanEmail=typeof email==='string'?email.trim().toLowerCase():'';
  if(!cleanName || cleanName.length>100)throw fail(400,'Enter a name of up to 100 characters.');
  if(!cleanEmail || cleanEmail.length>254)throw fail(400,'Enter a valid email or login ID.');
  if(typeof password!=='string' || password.length<5 || password.length>128)throw fail(400,'Use a password between 5 and 128 characters.');
  if(!['admin','lister','shipper'].includes(role))throw fail(400,'Choose a valid role.');
  const created=transaction(()=>{
    if(db.prepare('SELECT id FROM users WHERE email=?').get(cleanEmail))throw fail(409,'An account with this email already exists.');
    const result=db.prepare('INSERT INTO users(name,email,password_hash,role,active,must_change_password) VALUES(?,?,?,?,1,1)').run(cleanName,cleanEmail,hashPassword(password),role);
    const user=db.prepare('SELECT id,name,email,role,active,must_change_password,last_login_at FROM users WHERE id=?').get(result.lastInsertRowid);
    audit(req.user.id,'user',user.id,'created',`${user.name} created as ${user.role}.`);
    return user;
  });
  res.status(201).json(created);
});
app.patch('/api/team/:id/status',roles('admin'),(req,res)=>{
  const id=Number(req.params.id);if(!Number.isInteger(id))throw fail(400,'Invalid user.');
  if(typeof req.body.active!=='boolean')throw fail(400,'Choose Active or Suspended.');
  if(id===req.user.id && !req.body.active)throw fail(409,'You cannot suspend your own account.');
  const updated=transaction(()=>{const person=db.prepare('SELECT * FROM users WHERE id=?').get(id);if(!person)throw fail(404,'User not found.');db.prepare('UPDATE users SET active=? WHERE id=?').run(req.body.active?1:0,id);if(!req.body.active)db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);audit(req.user.id,'user',id,req.body.active?'activated':'suspended',`${person.name} marked ${req.body.active?'active':'suspended'}.`);return db.prepare('SELECT id,name,email,role,active,must_change_password,last_login_at FROM users WHERE id=?').get(id);});
  res.json(safeUser(updated));
});
app.post('/api/team/:id/reset-password',roles('admin'),(req,res)=>{
  const id=Number(req.params.id);const {password,confirmPassword}=req.body||{};
  if(!Number.isInteger(id))throw fail(400,'Invalid user.');
  if(typeof password!=='string'||password.length<5||password.length>128)throw fail(400,'Use a temporary password between 5 and 128 characters.');
  if(password!==confirmPassword)throw fail(400,'Temporary password and confirmation must match.');
  transaction(()=>{const person=db.prepare('SELECT * FROM users WHERE id=?').get(id);if(!person)throw fail(404,'User not found.');db.prepare('UPDATE users SET password_hash=?,must_change_password=1 WHERE id=?').run(hashPassword(password),id);db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);audit(req.user.id,'user',id,'password_reset',`Temporary password assigned to ${person.name}; sessions revoked.`);});
  res.json({ok:true});
});
const itemSelect = 'SELECT i.*,u.name AS owner_name FROM items i LEFT JOIN users u ON i.owner_id=u.id';
function filters(req) {
  const clauses = ['i.archived=?']; const args = [req.query.archived==='true'?1:0];
  if(req.query.q) {const q=String(req.query.q).slice(0,150);clauses.push("(i.title LIKE ? ESCAPE '\\' OR COALESCE(i.ebay_id,'') LIKE ? ESCAPE '\\' OR printf('FX-%05d',i.id) LIKE ? ESCAPE '\\')");const escaped=`%${q.replace(/[\\%_]/g,'\\$&')}%`;args.push(escaped,escaped,escaped);}
  if(req.query.owner==='mine') {clauses.push('i.owner_id=?');args.push(req.user.id);}
  if(req.query.owner==='unassigned') clauses.push('i.owner_id IS NULL');
  if(req.query.owner && /^\d+$/.test(req.query.owner)) {clauses.push('i.owner_id=?');args.push(Number(req.query.owner));}
  if(req.query.state==='unlinked') clauses.push('i.ebay_id IS NULL');
  if(req.query.state==='linked') clauses.push('i.ebay_id IS NOT NULL');
  return {where:clauses.join(' AND '),args};
}
app.get('/api/items',roles('admin','lister','shipper'),(req,res)=>{const {where,args}=filters(req);res.json(db.prepare(`${itemSelect} WHERE ${where} ORDER BY i.created_at DESC,i.id DESC`).all(...args));});
app.get('/api/items/export',roles('admin','lister'),(req,res)=>{
  const {where,args}=filters(req);const rows=db.prepare(`${itemSelect} WHERE ${where} ORDER BY i.id`).all(...args);
  const cell=v=>'"'+String(v??'').replace(/^[=+@\-\t\r]/,"'$&").replaceAll('"','""')+'"';
  const csv=[['Internal ID','Title','eBay ID','Price USD','Quantity','Location','Owner','Note','Archived'],...rows.map(i=>[`FX-${String(i.id).padStart(5,'0')}`,i.title,i.ebay_id,(i.price_cents/100).toFixed(2),i.quantity,i.location,i.owner_name,i.note,i.archived?'Yes':'No'])].map(r=>r.map(cell).join(',')).join('\r\n');
  res.set({'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="fashion-exchange-inventory.csv"'}).send('\uFEFF'+csv);
});
function itemById(id){const item=db.prepare(`${itemSelect} WHERE i.id=?`).get(id);if(!item)throw fail(404,'Item not found.');return item;}
app.get('/api/items/:id',roles('admin','lister','shipper'),(req,res)=>res.json(itemById(req.params.id)));
function validateItem(body,user,existing){
  const title=typeof body.title==='string'?body.title.trim():'';
  if(!title || title.length>180)throw fail(400,'Enter a title of up to 180 characters.');
  const price=typeof body.price==='string'?body.price.trim():'';
  if(!/^\d{1,7}(\.\d{1,2})?$/.test(price))throw fail(400,'Enter a valid price with no more than two decimal places.');
  const [dollars,cents='']=price.split('.');const priceCents=Number(dollars)*100+Number(cents.padEnd(2,'0'));
  if(!Number.isInteger(body.quantity)||body.quantity<0||body.quantity>100000)throw fail(400,'Quantity must be a whole number between 0 and 100,000.');
  const ebayId=typeof body.ebay_id==='string'?body.ebay_id.trim():'';
  if(ebayId && !/^(\d{6,20}|DEMO-\d{6,20})$/.test(ebayId))throw fail(400,'Use a numeric eBay listing ID (6–20 digits).');
  if(typeof body.location!=='string'||body.location.length>100||typeof body.note!=='string'||body.note.length>3000)throw fail(400,'Location or note is too long.');
  const owner=user.role==='admin'?(body.owner_id===null?null:Number(body.owner_id)):(existing?existing.owner_id:user.id);
  if(owner!==null && (!Number.isInteger(owner)||!db.prepare("SELECT id FROM users WHERE id=? AND role IN ('admin','lister')").get(owner)))throw fail(400,'Choose a valid owner.');
  if(user.role!=='admin' && body.owner_id !== undefined && body.owner_id !== owner)throw fail(403,'Only an administrator can change the owner.');
  return {title,ebay_id:ebayId||null,price_cents:priceCents,quantity:body.quantity,location:body.location.trim(),owner_id:owner,note:body.note.trim()};
}
function editable(item,user){if(user.role!=='admin' && item.owner_id!==user.id)throw fail(403,'You can only edit items assigned to you.');}
app.post('/api/items',roles('admin','lister'),(req,res)=>{
  const key=req.get('Idempotency-Key');if(!key||!/^[a-zA-Z0-9-]{16,80}$/.test(key))throw fail(400,'Missing save identifier. Refresh and try again.');
  const data=validateItem(req.body,req.user);const hash=sha(JSON.stringify(data));
  const result=transaction(()=>{
    const previous=db.prepare('SELECT id,request_hash FROM items WHERE created_by=? AND request_key=?').get(req.user.id,key);
    if(previous){if(previous.request_hash!==hash)throw fail(409,'This save was already used for different data. Reopen the form.');return itemById(previous.id);}
    const now=new Date().toISOString();
    const inserted=db.prepare('INSERT INTO items(title,ebay_id,price_cents,quantity,location,owner_id,note,created_by,created_at,updated_at,request_key,request_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(...Object.values(data),req.user.id,now,now,key,hash);
    audit(req.user.id,'item',Number(inserted.lastInsertRowid),'created',`${data.title} added to inventory.`);
    return itemById(inserted.lastInsertRowid);
  });res.status(201).json(result);
});
app.patch('/api/items/:id',roles('admin','lister'),(req,res)=>{
  const item=transaction(()=>{
    const previous=itemById(req.params.id);editable(previous,req.user);
    if(previous.archived)throw fail(409,'Restore this item before editing.');
    if(req.body.version!==previous.version)throw fail(409,'This item changed since you opened it. Close and reopen it to review the latest version.');
    const data=validateItem(req.body,req.user,previous);
    db.prepare('UPDATE items SET title=?,ebay_id=?,price_cents=?,quantity=?,location=?,owner_id=?,note=?,updated_at=?,version=version+1 WHERE id=?').run(...Object.values(data),new Date().toISOString(),previous.id);
    const diff=Object.entries(data).filter(([k,v])=>previous[k]!==v).map(([k,v])=>`${k}: ${previous[k]??'none'} → ${v??'none'}`).join('; ');
    audit(req.user.id,'item',previous.id,'updated',diff||'Saved without changes.');return itemById(previous.id);
  });res.json(item);
});
app.post('/api/items/:id/claim',roles('admin','lister'),(req,res)=>{
  const item=transaction(()=>{
    const previous=itemById(req.params.id);
    const changed=db.prepare('UPDATE items SET owner_id=?,version=version+1,updated_at=? WHERE id=? AND owner_id IS NULL AND archived=0').run(req.user.id,new Date().toISOString(),previous.id);
    if(!changed.changes)throw fail(409,'This item is already assigned or archived. Refresh the list.');
    audit(req.user.id,'item',previous.id,'claimed',`${req.user.name} claimed ${previous.title}.`);return itemById(previous.id);
  });res.json(item);
});
app.post('/api/items/:id/archive',roles('admin','lister'),(req,res)=>{
  const item=transaction(()=>{
    const previous=itemById(req.params.id);editable(previous,req.user);
    if(req.body.version!==previous.version)throw fail(409,'This item changed. Refresh and try again.');
    if(typeof req.body.archived!=='boolean')throw fail(400,'Invalid archive state.');
    if(req.body.archived && db.prepare("SELECT 1 FROM shipment_lines sl JOIN shipments s ON s.id=sl.shipment_id WHERE sl.item_id=? AND s.status!='shipped'").get(previous.id))throw fail(409,'This item is in an unfinished shipment. Complete the shipment before archiving.');
    db.prepare('UPDATE items SET archived=?,version=version+1,updated_at=? WHERE id=?').run(req.body.archived?1:0,new Date().toISOString(),previous.id);
    audit(req.user.id,'item',previous.id,req.body.archived?'archived':'restored',previous.title);return itemById(previous.id);
  });res.json(item);
});
app.get('/api/overview',(req,res)=>{
  const pending=db.prepare("SELECT count(*) AS n FROM shipments WHERE status!='shipped'").get().n;
  if(req.user.role==='shipper')return res.json({pending});
  const stats=db.prepare('SELECT count(*) AS total, COALESCE(sum(owner_id IS NULL),0) AS unassigned, COALESCE(sum(owner_id=?),0) AS mine, COALESCE(sum(price_cents*quantity),0) AS value FROM items WHERE archived=0').get(req.user.id);
  const recent=db.prepare(`${itemSelect} WHERE i.archived=0 ORDER BY i.created_at DESC LIMIT 5`).all();
  res.json({...stats,pending,recent});
});
app.get('/api/activity',(req,res)=>{
  let condition='1=1';const args=[];
  if(req.user.role==='lister'){condition='a.actor_id=?';args.push(req.user.id);}
  if(req.user.role==='shipper'){condition="a.entity_type='shipment'";}
  res.json(db.prepare(`SELECT a.*,u.name AS actor_name FROM audit a JOIN users u ON u.id=a.actor_id WHERE ${condition} ORDER BY a.id DESC LIMIT 30`).all(...args));
});
app.get('/api/shipments',roles('admin','shipper'),(req,res)=>{
  const shipments=db.prepare('SELECT s.*,p.name AS packed_name,u.name AS shipped_name FROM shipments s LEFT JOIN users p ON p.id=s.packed_by LEFT JOIN users u ON u.id=s.shipped_by ORDER BY s.created_at DESC').all();
  const lines=db.prepare('SELECT sl.shipment_id,sl.quantity,i.title,i.location FROM shipment_lines sl JOIN items i ON i.id=sl.item_id ORDER BY sl.shipment_id,sl.id').all();
  const byShipment=Map.groupBy(lines,line=>line.shipment_id);
  for(const shipment of shipments)shipment.lines=byShipment.get(shipment.id)||[];
  res.json(shipments);
});
app.post('/api/shipments/:id/advance',roles('admin','shipper'),(req,res)=>{
  transaction(()=>{
    const s=db.prepare('SELECT * FROM shipments WHERE id=?').get(req.params.id);if(!s)throw fail(404,'Shipment not found.');
    if(req.body?.version!==s.version)throw fail(409,'This shipment changed. Refresh before continuing.');
    if(s.status==='shipped')throw fail(409,'Already marked as shipped.');
    const next=s.status==='pending'?'packed':'shipped';const field=next==='packed'?'packed':'shipped';
    const tracking=typeof req.body?.tracking_number==='string'?req.body.tracking_number.trim():'';
    if(next==='shipped' && (!/^[A-Za-z0-9][A-Za-z0-9 -]{4,79}$/.test(tracking) || !/[A-Za-z0-9]/.test(tracking)))throw fail(400,'Enter a tracking number of 5 to 80 letters, numbers, spaces, or hyphens.');
    db.prepare(`UPDATE shipments SET status=?,${field}_at=?,${field}_by=?,tracking_number=?,version=version+1 WHERE id=?`).run(next,new Date().toISOString(),req.user.id,next==='shipped'?tracking:null,s.id);
    audit(req.user.id,'shipment',s.id,next,`${s.order_number} marked ${next} by ${req.user.name}${next==='shipped'?`; tracking ${tracking}`:''}.`);
  });res.json({ok:true});
});
app.use('/api',(req,res)=>res.status(404).json({error:'API route not found.'}));
app.use(express.static(resolve('dist')));
app.get('/{*path}',(req,res)=>res.sendFile(resolve('dist/index.html')));
app.use((error,req,res,next)=>{
  if(error.code==='ERR_SQLITE_ERROR' && String(error.message).includes('items.ebay_id'))return res.status(409).json({error:'This eBay listing ID is already saved. Find the existing item instead.'});
  if(error.code==='ERR_SQLITE_ERROR' && String(error.message).includes('users.email'))return res.status(409).json({error:'An account with this email already exists.'});
  const status=error.status || 500;
  if(status>=500)console.error(error);
  res.status(status).json({error:status>=500?'Could not save or load data. Your changes have not been confirmed; please try again.':error.message});
});
const host = process.env.HOST || '0.0.0.0';
const server=app.listen(port,host,error=>{
  if(error){console.error(`Could not start server: ${error.message}`);db.close();process.exitCode=1;return;}
  console.log(`Fashion Exchange ready at http://${host}:${port}`);
});
function shutdown(){server.close(()=>{db.close();process.exit(0);});}
process.on('SIGTERM',shutdown);process.on('SIGINT',shutdown);
