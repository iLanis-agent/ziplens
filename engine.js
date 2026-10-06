/* ZipLens engine - ZIP archive structure parser.
   Parses EOCD (+zip64), central directory, local headers; CRC-32; warnings.
   No deps. Browser global ZipLens, or module.exports in node. */
(function(root){
'use strict';
var SIG_LH=0x04034b50, SIG_CD=0x02014b50, SIG_EOCD=0x06054b50,
    SIG_EOCD64=0x06064b50, SIG_EOCD64LOC=0x07064b50, SIG_DD=0x08074b50;
var METHODS={0:'store',1:'shrink',6:'implode',8:'deflate',9:'deflate64',12:'bzip2',14:'lzma',93:'zstd',95:'xz',96:'jpeg',97:'wavpack',98:'ppmd',99:'aes'};
var CRCTAB=null;
function crcTable(){
  if(CRCTAB)return CRCTAB;
  var t=new Uint32Array(256),n,c,k;
  for(n=0;n<256;n++){c=n;for(k=0;k<8;k++)c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1);t[n]=c>>>0;}
  CRCTAB=t;return t;
}
function crc32(bytes){
  var t=crcTable(),c=0xFFFFFFFF,i;
  for(i=0;i<bytes.length;i++)c=t[(c^bytes[i])&0xFF]^(c>>>8);
  return (c^0xFFFFFFFF)>>>0;
}
function dosDate(dt,dm){
  return {year:((dm>>9)&0x7F)+1980, month:(dm>>5)&0xF, day:dm&0x1F,
          hour:(dt>>11)&0x1F, minute:(dt>>5)&0x3F, second:(dt&0x1F)*2,
          raw_time:dt, raw_date:dm};
}
function methodName(m){return METHODS[m]||('method-'+m);}
function u8s(view,off,len){
  var b=new Uint8Array(view.buffer,view.byteOffset+off,len),s='',i;
  for(i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);
  try{return decodeURIComponent(escape(s));}catch(e){return s;}
}
function parseZip(buf){
  var view=buf instanceof DataView?buf:new DataView(buf.buffer?buf.buffer.slice(buf.byteOffset,buf.byteOffset+buf.byteLength):buf);
  var len=view.byteLength, warnings=[], errors=[];
  function u16(o){return view.getUint16(o,true);}
  function u32(o){return view.getUint32(o,true);}
  /* EOCD: scan backwards over the last 65557 bytes for a sig whose
     comment length consumes exactly the rest of the file. */
  var eocdOff=-1,i;
  var scanFrom=Math.max(0,len-22-65535);
  for(i=len-22;i>=scanFrom;i--){
    if(i+22<=len && u32(i)===SIG_EOCD && i+22+u16(i+20)<=len){eocdOff=i;break;}
  }
  if(eocdOff<0){errors.push('end of central directory record not found');return {errors:errors,warnings:warnings,entries:[],segments:[]};}
  var disk=u16(eocdOff+4), cdDisk=u16(eocdOff+6),
      nDisk=u16(eocdOff+8), nTot=u16(eocdOff+10),
      cdSize=u32(eocdOff+12), cdOff=u32(eocdOff+16),
      commentLen=u16(eocdOff+20),
      comment=commentLen?u8s(view,eocdOff+22,commentLen):'';
  var zip64=false, eocd64=null;
  if(nDisk===0xFFFF||nTot===0xFFFF||cdSize===0xFFFFFFFF||cdOff===0xFFFFFFFF){
    zip64=true;
    var locOff=eocdOff-20;
    if(locOff>=0 && u32(locOff)===SIG_EOCD64LOC){
      var e64=u32(locOff+8);
      if(e64+56<=len && u32(e64)===SIG_EOCD64){
        eocd64={offset:e64, disk:u32(e64+16), cdDisk:u32(e64+20),
                nDisk:Number(view.getBigUint64(e64+24,true)), nTot:Number(view.getBigUint64(e64+32,true)),
                cdSize:Number(view.getBigUint64(e64+40,true)), cdOff:Number(view.getBigUint64(e64+48,true))};
        cdOff=eocd64.cdOff; cdSize=eocd64.cdSize; nTot=eocd64.nTot;
      } else errors.push('zip64 EOCD locator points at a bad record');
    } else errors.push('zip64 sentinel values but no EOCD64 locator');
  }
  if(disk!==0||cdDisk!==0) warnings.push('multi-disk archive (spanning) - not fully supported');
  /* prepended data (sfx stub / concat): zipfile-style shift */
  var concatShift=eocdOff-(cdOff+cdSize);
  if(concatShift>0)warnings.push(concatShift+' byte(s) before the first local header (prepended data, e.g. self-extracting stub)');
  var entries=[], segments=[];
  var off=cdOff+ (concatShift>0?concatShift:0), cdEnd=off+cdSize, count=0;
  if(cdOff<0||cdOff>len){errors.push('central directory offset out of range');return {errors:errors,warnings:warnings,entries:entries,segments:segments};}
  while(off+46<=cdEnd+0 && u32(off)===SIG_CD){
    var flags=u16(off+8), method=u16(off+10),
        dt=u16(off+12), dm=u16(off+14),
        crc=u32(off+16), csize=u32(off+20), usize=u32(off+24),
        nlen=u16(off+28), xlen=u16(off+30), clen=u16(off+32),
        diskNo=u16(off+34), xattr=u32(off+38), lho=u32(off+42);
    var name=u8s(view,off+46,nlen);
    var ecomment=clen?u8s(view,off+46+nlen+xlen,clen):'';
    var eoff=off;
    off+=46+nlen+xlen+clen; count++;
    var e={index:count, name:name, flags:flags, method:method, method_name:methodName(method),
           date:dosDate(dt,dm), crc:crc, csize:csize, usize:usize,
           lho:lho, comment:ecomment, attrs:xattr, cd_offset:eoff,
           encrypted:!!(flags&1), data_descriptor:!!(flags&8), utf8:!!(flags&0x800),
           zip64:false, local:null};
    /* zip64 extra 0x0001 in central extra field */
    var xoff=off-xlen-clen, xend=xoff+xlen, x=off- clen - xlen;
    for(x=off-clen-xlen; x+4<=off-clen; ){
      var hid=u16(x), hlen=u16(x+2);
      if(hid===0x0001){e.zip64=true; var p=x+4;
        if(e.usize===0xFFFFFFFF){e.usize=Number(view.getBigUint64(p,true));p+=8;}
        if(e.csize===0xFFFFFFFF){e.csize=Number(view.getBigUint64(p,true));p+=8;}
        if(e.lho===0xFFFFFFFF){e.lho=Number(view.getBigUint64(p,true));p+=8;}
        break;}
      x+=4+hlen;
    }
    if(e.encrypted)warnings.push('entry "'+e.name+'" is encrypted - contents not checked');
    if(e.method!==0&&e.method!==8)warnings.push('entry "'+e.name+'" uses '+e.method_name+' - content check unsupported');
    /* local header */
    if(concatShift>0)e.lho+=concatShift;
    if(e.lho+30<=len && u32(e.lho)===SIG_LH){
      var lnlen=u16(e.lho+26), lxlen=u16(e.lho+28);
      var lflags=u16(e.lho+6), lmethod=u16(e.lho+8), lcrc=u32(e.lho+14),
          lcsize=u32(e.lho+18), lusize=u32(e.lho+22);
      var lname=u8s(view,e.lho+30,lnlen);
      e.local={offset:e.lho, name:lname, data_off:e.lho+30+lnlen+lxlen,
               flags:lflags, method:lmethod, crc:lcrc, csize:lcsize, usize:lusize};
      if(lflags!==e.flags)warnings.push('entry "'+e.name+'": local/central flag mismatch');
      if(lmethod!==e.method)warnings.push('entry "'+e.name+'": local/central method mismatch');
      if(!e.data_descriptor&&(lcrc!==e.crc||lcsize!==e.csize))warnings.push('entry "'+e.name+'": local/central CRC or size mismatch');
      segments.push({kind:'local', entry:count, off:e.lho, len:30+lnlen+lxlen});
      segments.push({kind:'data', entry:count, off:e.local.data_off, len:e.csize});
    } else {
      warnings.push('entry "'+e.name+'": local header missing at offset '+e.lho);
    }
    segments.push({kind:'central', entry:count, off:e.cd_offset, len:46+u16(e.cd_offset+28)+u16(e.cd_offset+30)+u16(e.cd_offset+32)});
    entries.push(e);
  }
  if(count!==nTot)warnings.push('central directory holds '+count+' entries but EOCD says '+nTot);
  if(cdOff+cdSize!==eocdOff)warnings.push('central directory does not end where the EOCD begins');
  segments.push({kind:'eocd', off:eocdOff, len:22+commentLen});
  if(eocd64){segments.push({kind:'eocd64', off:eocd64.offset, len:56});segments.push({kind:'eocd64loc', off:eocdOff-20, len:20});}
  if(eocdOff+22+commentLen<len)warnings.push((len-(eocdOff+22+commentLen))+' trailing bytes after EOCD');
  return {errors:errors, warnings:warnings, entries:entries, segments:segments,
          eocd:{offset:eocdOff, entries:nTot, cd_size:cdSize, cd_offset:cdOff, comment:comment}, concat_shift:concatShift>0?concatShift:0,
          zip64:zip64, size:len};
}
function verifyEntry(fileBytes, e){
  /* returns Promise<'ok'|'bad-crc'|'bad-size'|'skipped'> */
  if(e.encrypted)return Promise.resolve('skipped');
  if(e.method!==0&&e.method!==8)return Promise.resolve('skipped');
  if(!e.local)return Promise.resolve('skipped');
  var data=fileBytes.slice(e.local.data_off, e.local.data_off+e.csize);
  if(e.method===0){
    return Promise.resolve(crc32(data)===e.crc?'ok':'bad-crc');
  }
  var ds=new DecompressionStream('deflate-raw');
  var stream=new Blob([data]).stream().pipeThrough(ds);
  return new Response(stream).arrayBuffer().then(function(ab){
    var out=new Uint8Array(ab);
    if(out.length!==e.usize)return 'bad-size';
    return crc32(out)===e.crc?'ok':'bad-crc';
  },function(){return 'bad-crc';});
}
var api={parseZip:parseZip, crc32:crc32, verifyEntry:verifyEntry, methodName:methodName};
if(typeof module!=='undefined'&&module.exports)module.exports=api;
root.ZipLens=api;
})(typeof self!=='undefined'?self:this);
