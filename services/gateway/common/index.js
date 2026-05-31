const path = require('path');
require('dotenv').config({ path: process.env.ENV_FILE || path.resolve(__dirname, '../../../.env') });
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const { createClient } = require('redis');

function cleanDatabaseUrl(raw){
  if(!raw) return raw;
  try{
    const u=new URL(raw);
    ['sslmode','sslcert','sslkey','sslrootcert'].forEach(k=>u.searchParams.delete(k));
    return u.toString();
  }catch(e){ return raw.replace(/[?&]sslmode=[^&]+/,''); }
}
const rawDatabaseUrl = process.env.DATABASE_URL || '';
const forceSsl = process.env.PGSSL === 'true' || process.env.PGSSLMODE === 'require' || /supabase\.(co|com)|pooler\.supabase\.com/.test(rawDatabaseUrl);
const pool = new Pool({
  connectionString: cleanDatabaseUrl(rawDatabaseUrl),
  ssl: forceSsl ? { rejectUnauthorized: false } : false,
  max: Number(process.env.PG_POOL_MAX || 20),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

function asyncHandler(fn){ return (req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next); }
function signStaffToken(user){ return jwt.sign({ type:'staff', id:user.id, username:user.username, fullName:user.full_name, role:user.role, branchId:user.branch_id, branchName:user.branch_name }, process.env.JWT_SECRET || 'coffee_secret', { expiresIn:'8h' }); }
function signCustomerToken(customer){ return jwt.sign({ type:'customer', id:customer.id, username:customer.username || customer.phone, fullName:customer.name, role:'customer', customerId:customer.id }, process.env.JWT_SECRET || 'coffee_secret', { expiresIn:'8h' }); }
function authRequired(req,res,next){ const header=req.headers.authorization || ''; const token=header.startsWith('Bearer ')?header.slice(7):null; if(!token) return res.status(401).json({message:'Chưa đăng nhập'}); try{ req.user=jwt.verify(token, process.env.JWT_SECRET || 'coffee_secret'); next(); } catch(e){ res.status(401).json({message:'Token không hợp lệ'}); } }
function allowRoles(...roles){ return (req,res,next)=>{ if(!req.user || !roles.includes(req.user.role)) return res.status(403).json({message:'Không đủ quyền'}); next(); }; }
function staffOnly(req,res,next){ if(!req.user || req.user.type!=='staff') return res.status(403).json({message:'Chỉ nhân sự hệ thống được phép truy cập'}); next(); }
function customerOnly(req,res,next){ if(!req.user || req.user.type!=='customer') return res.status(403).json({message:'Chỉ khách hàng được phép truy cập'}); next(); }
function isAdmin(req){ return req.user?.role==='admin'; }
function isManager(req){ return req.user?.role==='manager'; }
function managerBranchGuard(req, branchId){ return isAdmin(req) || Number(req.user?.branchId)===Number(branchId); }
async function createRedisClient(){ const client=createClient({url:process.env.REDIS_URL||'redis://localhost:6379'}); client.on('error',err=>console.error('[Redis]',err.message)); await client.connect(); return client; }
module.exports={pool,asyncHandler,signStaffToken,signCustomerToken,authRequired,allowRoles,staffOnly,customerOnly,isAdmin,isManager,managerBranchGuard,createRedisClient};
