import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

export const databasePath = resolve(process.env.FX_DB || 'data/fashionexchange.sqlite');
mkdirSync(dirname(databasePath), { recursive: true, mode: 0o700 });
export const db = new DatabaseSync(databasePath);
db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  return `${salt}:${scryptSync(password, salt, 64).toString('hex')}`;
}
export function verifyPassword(password, hash) {
  const [salt, expected] = hash.split(':');
  const actual = scryptSync(password, salt, 64);
  return timingSafeEqual(actual, Buffer.from(expected, 'hex'));
}
export function transaction(fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const result = fn(); db.exec('COMMIT'); return result; }
  catch (error) { db.exec('ROLLBACK'); throw error; }
}
db.exec(`
CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','lister','shipper')),
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 must_change_password INTEGER NOT NULL DEFAULT 0 CHECK(must_change_password IN (0,1)),
 last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires_at INTEGER NOT NULL,
 last_seen_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS items (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, ebay_id TEXT UNIQUE,
 price_cents INTEGER NOT NULL CHECK(price_cents >= 0), quantity INTEGER NOT NULL CHECK(quantity >= 0),
 location TEXT NOT NULL DEFAULT '', owner_id INTEGER REFERENCES users(id), note TEXT NOT NULL DEFAULT '',
 category TEXT NOT NULL DEFAULT 'Other', archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0,1)),
 version INTEGER NOT NULL DEFAULT 1, created_by INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 request_key TEXT, request_hash TEXT, UNIQUE(created_by,request_key)
);
CREATE TABLE IF NOT EXISTS shipments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, order_number TEXT NOT NULL UNIQUE, recipient TEXT NOT NULL,
 destination TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','packed','shipped')),
 version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
 packed_at TEXT, packed_by INTEGER REFERENCES users(id), shipped_at TEXT, shipped_by INTEGER REFERENCES users(id),
 tracking_number TEXT
);
CREATE TABLE IF NOT EXISTS shipment_lines (
 id INTEGER PRIMARY KEY AUTOINCREMENT, shipment_id INTEGER NOT NULL REFERENCES shipments(id),
 item_id INTEGER NOT NULL REFERENCES items(id), quantity INTEGER NOT NULL CHECK(quantity > 0)
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER NOT NULL REFERENCES users(id),
 entity_type TEXT NOT NULL, entity_id INTEGER NOT NULL, action TEXT NOT NULL,
 detail TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS items_owner ON items(owner_id);
CREATE INDEX IF NOT EXISTS audit_entity ON audit(entity_type,entity_id);
CREATE INDEX IF NOT EXISTS sessions_expiration ON sessions(expires_at);
INSERT OR IGNORE INTO schema_migrations VALUES (1, datetime('now'));
`);

const userColumns=new Set(db.prepare('PRAGMA table_info(users)').all().map(column=>column.name));
if(!userColumns.has('active'))db.exec('ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))');
if(!userColumns.has('must_change_password'))db.exec('ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0 CHECK(must_change_password IN (0,1))');
if(!userColumns.has('last_login_at'))db.exec('ALTER TABLE users ADD COLUMN last_login_at TEXT');
const sessionColumns=new Set(db.prepare('PRAGMA table_info(sessions)').all().map(column=>column.name));
if(!sessionColumns.has('last_seen_at'))db.exec('ALTER TABLE sessions ADD COLUMN last_seen_at INTEGER NOT NULL DEFAULT 0');
if(!db.prepare('SELECT 1 FROM schema_migrations WHERE version=2').get())transaction(()=>{
  const original=db.prepare("SELECT id FROM users WHERE id=1 AND role='admin'").get();
  if(original)db.prepare('UPDATE users SET email=?,password_hash=?,active=1,must_change_password=1 WHERE id=?').run('Admin',hashPassword('Welcome!'),original.id);
  db.prepare("INSERT INTO schema_migrations VALUES (2,datetime('now'))").run();
});
const shipmentColumns=new Set(db.prepare('PRAGMA table_info(shipments)').all().map(column=>column.name));
if(!shipmentColumns.has('tracking_number'))db.exec('ALTER TABLE shipments ADD COLUMN tracking_number TEXT');
if(!db.prepare('SELECT 1 FROM schema_migrations WHERE version=3').get())db.prepare("INSERT INTO schema_migrations VALUES (3,datetime('now'))").run();

export function audit(userId, type, id, action, detail) {
  db.prepare('INSERT INTO audit(actor_id,entity_type,entity_id,action,detail,created_at) VALUES(?,?,?,?,?,?)')
    .run(userId, type, id, action, detail, new Date().toISOString());
}
if (!db.prepare('SELECT id FROM users LIMIT 1').get()) {
  const password = process.env.FX_DEMO_PASSWORD || 'qwertymarket123';
  transaction(() => {
    const insertUser = db.prepare('INSERT INTO users(id,name,email,password_hash,role,must_change_password) VALUES(?,?,?,?,?,?)');
    insertUser.run(1,'Administrator','Admin',hashPassword(password),'admin',0);
    for (const u of [[2,'Arseniy','arseniy@fashionexchange.local','lister'],[3,'Sam','shipping@fashionexchange.local','shipper']])
      insertUser.run(u[0],u[1],u[2],hashPassword(password),u[3],0);
    const products = [
      ['Coach leather shoulder bag',8900,1,'A · 12',2,'Bags'],
      ['Burberry wool trench coat',24500,1,'B · 04',null,'Clothing'],
      ['Chanel vintage clip-on earrings',12500,1,'J · 02',2,'Jewelry'],
      ['Prada nylon crossbody bag',18500,1,'A · 08',null,'Bags'],
      ['Ralph Lauren cable-knit sweater',4800,2,'B · 11',2,'Clothing'],
      ['Salvatore Ferragamo loafers',9500,1,'S · 06',1,'Shoes'],
      ['Hermès silk scarf · blue',16500,1,'C · 03',null,'Accessories'],
      ['Levi’s 501 vintage jeans',6500,1,'B · 16',2,'Clothing'],
      ['Tumi leather travel wallet',4200,1,'C · 07',1,'Accessories'],
      ['Versace embroidered jacket',19500,1,'B · 02',null,'Clothing'],
      ['Chanel gold-tone buttons',2799,5,'J · 09',2,'Accessories'],
      ['New Balance 990 sneakers',7800,1,'S · 03',null,'Shoes'],
      ['Kate Spade structured tote',5800,1,'A · 05',2,'Bags'],
      ['Dior vintage pendant necklace',11500,1,'J · 04',1,'Jewelry'],
      ['Max Mara cashmere cardigan',13500,1,'B · 08',2,'Clothing'],
      ['Gucci leather belt',9900,1,'C · 01',null,'Accessories'],
      ['Linen button-down shirt',3200,1,'B · 19',2,'Clothing'],
      ['Vintage suede ankle boots',6800,1,'S · 12',1,'Shoes']
    ];
    const insertItem = db.prepare(`INSERT INTO items(title,ebay_id,price_cents,quantity,location,owner_id,category,note,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`);
    products.forEach((p,i) => {
      const date = new Date(Date.now() - i * 3600000 * 5).toISOString();
      insertItem.run(p[0],i % 4 === 0 ? null : `DEMO-${100001+i}`,p[1],p[2],p[3],p[4],p[5],'Fictional sample item. Not connected to a marketplace.',1,date,date);
    });
    const insertShip = db.prepare('INSERT INTO shipments(order_number,recipient,destination,created_at) VALUES(?,?,?,?)');
    for (let i=0; i<5; i++) {
      const result = insertShip.run(`DEMO-${2401+i}`,['Alex Taylor','Morgan Lee','Jamie Smith','Casey Parker','Jordan Ellis'][i],['San Francisco, CA','Portland, OR','Austin, TX','Seattle, WA','Boston, MA'][i],new Date(Date.now()-i*5400000).toISOString());
      db.prepare('INSERT INTO shipment_lines(shipment_id,item_id,quantity) VALUES(?,?,?)').run(result.lastInsertRowid,i+1,1);
    }
    audit(1,'workspace',1,'initialized','Sample workspace created with fictional inventory and orders.');
  });
  if (!process.env.FX_DEMO_PASSWORD) writeFileSync(resolve(dirname(databasePath),'demo-accounts.txt'),
    `LOCAL DEMO ACCOUNTS — do not publish\n\nDefault administrator login: Admin\nDefault administrator password: Welcome!\nA password change is required immediately after the first login.\n\nLister: arseniy@fashionexchange.local\nShipping: shipping@fashionexchange.local\nLister and shipper initial password: ${password}\n\nPasswords can be changed in Profile Settings.\n`,{mode:0o600});
}
