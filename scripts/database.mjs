import { DatabaseSync } from 'node:sqlite';
import { existsSync, mkdirSync, copyFileSync, chmodSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
const [command, input, output] = process.argv.slice(2);
function check(path) {
 const db = new DatabaseSync(path, {readOnly:true});
 try {
  const checks=db.prepare('PRAGMA integrity_check').all();
  if(checks.some(r=>r.integrity_check!=='ok')) throw new Error('Database integrity check failed.');
  if(db.prepare('PRAGMA foreign_key_check').all().length)throw new Error('Foreign-key check failed.');
  const version=db.prepare('SELECT MAX(version) AS version FROM schema_migrations').get().version;
  if(![1,2,3].includes(version))throw new Error('Unsupported database version.');
  return {items:db.prepare('SELECT count(*) AS count FROM items').get().count,shipments:db.prepare('SELECT count(*) AS count FROM shipments').get().count};
 } finally {db.close();}
}
try {
 if(command==='backup') {
  const source=resolve(process.env.FX_DB || 'data/fashionexchange.sqlite');
  if(!existsSync(source))throw new Error('Start the application once to create the database.');
  const target=resolve(input || `backups/fashionexchange-${new Date().toISOString().replaceAll(':','-')}.sqlite`);
  if(existsSync(target))throw new Error('Destination exists. Choose a new backup filename.');
  mkdirSync(dirname(target),{recursive:true,mode:0o700});
  const db=new DatabaseSync(source);db.exec('PRAGMA busy_timeout=5000');
  try{db.prepare('VACUUM INTO ?').run(target);}finally{db.close();}
  chmodSync(target,0o600);
  console.log(JSON.stringify({backup:target,...check(target)},null,2));
 } else if(command==='restore') {
  if(!input || !output)throw new Error('Usage: npm run restore -- backups/backup.sqlite data/restored.sqlite');
  const source=resolve(input),target=resolve(output);
  if(source===target || existsSync(target) || existsSync(target+'-wal') || existsSync(target+'-shm'))throw new Error('Restore only supports a NEW destination file. Existing data will not be overwritten.');
  const counts=check(source);mkdirSync(dirname(target),{recursive:true,mode:0o700});
  copyFileSync(source,target);chmodSync(target,0o600);
  const db=new DatabaseSync(target);try{db.exec('DELETE FROM sessions;');}finally{db.close();}
  console.log(JSON.stringify({restored:target,sessions:'cleared',...counts,...check(target)},null,2));
 } else throw new Error('Choose backup or restore.');
} catch(error){console.error(error.message);process.exitCode=1;}
