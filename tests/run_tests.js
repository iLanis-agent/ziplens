/* ZipLens test runner: engine vs tests/expected.json (from oracle.py / real zipfile). */
const fs=require('fs'), path=require('path');
const Z=require(path.join(__dirname,'..','engine.js'));
const exp=JSON.parse(fs.readFileSync(path.join(__dirname,'expected.json'),'utf8'));
let checks=0, fails=0;
function ok(cond,msg){checks++; if(!cond){fails++; console.log('FAIL',msg);}}
function eq(a,b,msg){ok(a===b,msg+' (exp '+JSON.stringify(b)+' got '+JSON.stringify(a)+')');}
(async function(){
eq(Z.crc32(Buffer.from('123456789')),0xCBF43926,'crc32 vector');
eq(Z.crc32(Buffer.alloc(0)),0,'crc32 empty');
for(const it of exp.items){
  let bytes;
  const zp=path.join(__dirname,'corpus',it.file);
  if(fs.existsSync(zp))bytes=fs.readFileSync(zp);
  else bytes=Buffer.from(fs.readFileSync(zp+'.b64','utf8').trim(),'base64');
  const r=Z.parseZip(bytes);
  eq(r.errors.length,0,it.file+': no parse errors');
  eq(r.entries.length,it.entries.length,it.file+': entry count');
  eq(r.eocd.comment,it.comment,it.file+': archive comment');
  eq(r.eocd.offset,it.eocd.offset,it.file+': eocd offset');
  eq(r.eocd.entries,it.eocd.entries,it.file+': eocd count');
  eq(r.eocd.cd_size,it.eocd.cd_size,it.file+': cd size');
  eq(r.eocd.cd_offset,it.eocd.cd_offset,it.file+': cd offset');
  // warnings derived from oracle facts
  const hasWarn=s=>r.warnings.some(w=>w.indexOf(s)>=0);
  eq(hasWarn('trailing bytes'), it.eocd.trailing>0, it.file+': trailing warning');
  const minLho=it.entries.length?Math.min.apply(null,it.entries.map(e=>e.lho)):0;
  eq(hasWarn('prepended data'), minLho>0, it.file+': prepended warning');
  for(let i=0;i<it.entries.length;i++){
    const a=r.entries[i], b=it.entries[i], p=it.file+'/'+b.name;
    eq(a.name,b.name,p+': name');
    eq(a.method,b.method,p+': method');
    eq(a.flags,b.flags,p+': flags');
    eq(a.crc,b.crc,p+': crc');
    eq(a.csize,b.csize,p+': csize');
    eq(a.usize,b.usize,p+': usize');
    eq(a.lho,b.lho,p+': lho');
    eq(a.comment,b.comment,p+': entry comment');
    eq(a.date.raw_time,b.raw_time,p+': dos time');
    eq(a.date.raw_date,b.raw_date,p+': dos date');
    eq(a.date.year,b.date.year,p+': year');
    eq(a.date.second,b.date.second,p+': second');
    ok(a.local&&a.local.data_off===b.local_data_off,p+': local data offset');
    eq(a.local.name,b.local_name,p+': local name');
    if(b.content_ok!==undefined){
      const v=await Z.verifyEntry(new Uint8Array(bytes.buffer,bytes.byteOffset,bytes.byteLength),a);
      eq(v,'ok',p+': content crc via '+a.method_name);
    }
  }
  // segments tile known structure: every cd/eocd segment in range
  for(const s of r.segments){ok(s.off>=0&&s.off+s.len<=r.size,it.file+': segment '+s.kind+' in range');}
}
console.log(checks+' checks, '+fails+' failures');
process.exit(fails?1:0);
})().catch(e=>{console.error(e);process.exit(1);});
