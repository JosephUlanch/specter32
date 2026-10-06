/* Offline structural assessment of SPECTER32 raw-802.11 PCAPs.
 * No password guessing or MIC verification. Keep this parser independent of UI.
 */
(function(root) {
'use strict';
const LIMIT=256*1024, WINDOW=5000000, ZERO32='0'.repeat(64);
const hex=a=>Array.from(a,b=>b.toString(16).padStart(2,'0')).join('');
const nonzero=a=>a.some(b=>b!==0);
const mac=a=>Array.from(a,b=>b.toString(16).padStart(2,'0')).join(':');
const u16=(p,i)=>p[i]|p[i+1]<<8;
const be16=(p,i)=>p[i]<<8|p[i+1];
const verdict=(status,label,detail,extra={})=>({status,label,detail,...extra});

// Parse RSN/WPA suite lists conservatively. Unknown and mixed AKMs need review.
function suites(p,oui) {
 if(p.length<8||u16(p,0)!==1)return null;
 let i=6,count=u16(p,i);i+=2;
 if(!count||i+count*4+2>p.length)return null;i+=count*4;
 count=u16(p,i);i+=2;
 if(!count||i+count*4>p.length)return null;
 const result=[];
 for(let n=0;n<count;n++,i+=4)result.push(hex(p.subarray(i,i+3))===oui?p[i+3]:-1);
 return result;
}
function tags(p) {
 let ssid=null,akms=[],bad=false;
 for(let i=0;i<p.length;) {
  if(i+2>p.length){bad=true;break;}
  const id=p[i++],length=p[i++];
  if(i+length>p.length){bad=true;break;}
  const data=p.subarray(i,i+length);i+=length;
  if(id===0&&length<=32&&nonzero(data))ssid=hex(data);
  let list;
  if(id===48)list=suites(data,'000fac');
  else if(id===221&&hex(data.subarray(0,4))==='0050f201')list=suites(data.subarray(4),'0050f2');
  else continue;
  if(!list)bad=true;else akms.push(...list);
 }
 return {ssid,akms,bad};
}
function personal(akms,version) {
 // Classic PSK with key versions 1/2; PSK-SHA256 with AES-CMAC version 3.
 return akms.length>0&&akms.every(a=>a===2||a===6)&&
        (version===3?akms.every(a=>a===6):akms.every(a=>a===2));
}
function analyze(input,expectedBssid='') {
 try {return inspect(input,expectedBssid.toLowerCase());}
 catch(e){return verdict('review','Capture needs review',e.message||'Could not read this PCAP.');}
}
function inspect(input,expected) {
 const p=input instanceof Uint8Array?input:new Uint8Array(input);
 if(p.length>LIMIT)throw Error('Capture exceeds the on-device analysis size limit.');
 if(p.length<24)throw Error('PCAP header is missing or truncated.');
 const signature=hex(p.subarray(0,4));
 const little=['d4c3b2a1','4d3cb2a1'].includes(signature);
 const nano=['4d3cb2a1','a1b23c4d'].includes(signature);
 if(!['d4c3b2a1','a1b2c3d4','4d3cb2a1','a1b23c4d'].includes(signature))throw Error('Unsupported file format; expected a SPECTER32 PCAP.');
 const view=new DataView(p.buffer,p.byteOffset,p.byteLength),get=i=>view.getUint32(i,little);
 if(view.getUint16(4,little)!==2||view.getUint16(6,little)!==4||get(20)!==105)throw Error('Unsupported PCAP version or link type; inspect on a computer.');
 const aps=new Map(),groups=new Map();let frames=0,eapol=0,keys=0;
 for(let offset=24;offset<p.length;) {
  if(offset+16>p.length)throw Error('Truncated PCAP record. Earlier packets may still be recoverable.');
  const sec=get(offset),fraction=get(offset+4),size=get(offset+8),original=get(offset+12);
  if(fraction>=(nano?1e9:1e6)||size!==original||size>1600||size>get(16)||offset+16+size>p.length)throw Error('Truncated or invalid packet record. Inspect this file on a computer.');
  const time=sec*1e6+fraction/(nano?1000:1),f=p.subarray(offset+16,offset+16+size);offset+=16+size;frames++;
  if(f.length<24||(f[0]&3))continue;
  const type=f[0]>>2&3,sub=f[0]>>4,ds=f[1]&3;
  if(type===0&&(sub===8||sub===5)&&f.length>=36) {
   const ap=mac(f.subarray(16,22));
   if(expected&&ap!==expected||mac(f.subarray(10,16))!==ap)continue;
   const t=tags(f.subarray(36));if(t.bad)continue;
   const info=aps.get(ap)||{ssids:new Set(),akms:new Set()};
   if(t.ssid)info.ssids.add(t.ssid);for(const a of t.akms)info.akms.add(a);aps.set(ap,info);continue;
  }
  if(type!==2||(ds!==1&&ds!==2)||(f[1]&0x44)||(f[22]&15)||(sub&4))continue;
  const ap=mac(f.subarray(ds===1?4:10,ds===1?10:16));
  if(expected&&ap!==expected)continue;
  const clientBytes=f.subarray(ds===1?10:4,ds===1?16:10),client=mac(clientBytes);
  // Infrastructure EAPOL must originate from the AP/client, not a relayed source.
  if(clientBytes[0]&1||!nonzero(clientBytes)||client===ap||mac(f.subarray(16,22))!==ap)continue;
  let h=24;
  if(sub&8){if(f.length<h+2||(f[h]&128))continue;h+=2;if(f[1]&128)h+=4;}
  if(f.length<h+12||hex(f.subarray(h,h+8))!=='aaaa03000000888e')continue;
  eapol++;
  const e=f.subarray(h+8),length=be16(e,2);
  if(e[0]<1||e[0]>3||e[1]!==3||length<95||length+4>e.length||![2,254].includes(e[4]))continue;
  const info=be16(e,5),version=info&7,keyLength=be16(e,97);
  if(!(info&8)||(info&0x0c00)||keyLength!==length-95)continue;
  const ack=!!(info&128),mic=!!(info&256),secure=!!(info&512),install=!!(info&64);
  const nonce=hex(e.subarray(17,49)),hasNonce=nonce!==ZERO32,hasMic=nonzero(e.subarray(81,97));
  let message=0;
  if(ack&&ds===2&&!mic&&!install&&!secure&&hasNonce&&!hasMic)message=1;
  if(ack&&ds===2&&mic&&install&&hasNonce&&hasMic)message=3;
  if(!ack&&ds===1&&mic&&!install&&hasMic)message=secure||!hasNonce?4:2;
  if(!message)continue;
  const replay=new DataView(e.buffer,e.byteOffset,e.byteLength).getBigUint64(9,false);
  const selection=message===2?tags(e.subarray(99,99+keyLength)):null;
  const k={message,ap,client,time,replay,nonce,version,descriptor:e[4],selection,length:length+4};
  const groupKey=ap+'/'+client+'/'+e[4]+'/'+version;
  if(!groups.has(groupKey))groups.set(groupKey,[]);
  groups.get(groupKey).push(k);keys++;
 }
 let best=null,review=null,operations=0;
 const within=(a,b)=>{if(++operations>200000)throw Error('Too many matching candidates; inspect this capture on a computer.');return Math.abs(a.time-b.time)<=WINDOW;};
 function assess(apMessage,clientMessage,complete=false) {
  const apInfo=aps.get(apMessage.ap),selection=clientMessage.selection;
  // M2 describes the client's actual AKM choice, including on WPA2/WPA3 APs.
  const akms=selection?.akms.length?selection.akms:Array.from(apInfo?.akms||[]);
  const extra={pair:`M${apMessage.message}+M${clientMessage.message}`,client:clientMessage.client,ap:apMessage.ap,complete};
  if(selection?.bad||![1,2,3].includes(clientMessage.version)||!personal(akms,clientMessage.version)||clientMessage.length>255){
   review=verdict('review','Pair found · needs review','Authentication type or EAPOL format is not confirmed as supported WPA/WPA2-Personal.',extra);return;
  }
  if(!apInfo||apInfo.ssids.size!==1){
   review=verdict('missing_ssid','Pair found · SSID needed','The PCAP needs one unambiguous network name from a beacon/probe response for standalone conversion.',extra);return;
  }
  const detail=`${extra.pair} matched for client ${extra.client}. Nonces, replay counters and SSID present. Password/MIC not verified.`;
  if(!best||complete)best=verdict(complete?'complete':'usable',complete?'Complete handshake':'Usable handshake pair',detail,extra);
 }
 for(const list of groups.values()) {
  const buckets=new Map();
  for(const k of list){const id=k.message+'/'+k.replay;if(!buckets.has(id))buckets.set(id,[]);buckets.get(id).push(k);}
  const get=(m,r)=>buckets.get(m+'/'+r)||[];
  for(const two of list.filter(k=>k.message===2)) {
   const ones=get(1,two.replay).filter(k=>within(k,two));
   const threes=get(3,two.replay+1n).filter(k=>within(k,two));
   for(const one of ones)assess(one,two);
   for(const three of threes)assess(three,two);
   for(const one of ones)for(const three of threes) {
    if(!within(one,three)||one.nonce!==three.nonce)continue;
    const four=get(4,three.replay).find(k=>within(k,one)&&within(k,two)&&within(k,three)&&(k.nonce===ZERO32||k.nonce===two.nonce));
    if(four)assess(one,two,true);
   }
  }
  // Rare M4 variants preserve SNonce and can form a usable pair without M2.
  for(const four of list.filter(k=>k.message===4&&k.nonce!==ZERO32)) {
   for(const one of get(1,four.replay-1n))if(within(one,four))assess(one,four);
   for(const three of get(3,four.replay))if(within(three,four))assess(three,four);
  }
 }
 if(best)return {...best,frames,eapol};
 if(review)return {...review,frames,eapol};
 if(eapol)return verdict('incomplete','Incomplete handshake','No supported matching message pair found. Retry with a client reconnecting during capture.',{frames,eapol,keys});
 return verdict('none','No handshake','No EAPOL authentication frames found in this capture.',{frames,eapol});
}
const api={analyze};
if(typeof module!=='undefined'&&module.exports)module.exports=api;
else root.SpecterHandshake=api;
})(typeof globalThis!=='undefined'?globalThis:this);
