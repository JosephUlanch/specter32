// Synthetic packet fixtures; deliberately not captures from nearby networks.
const AP='102030405060',CLIENT='a0b0c0d0e0f0';
const bytes=s=>Buffer.from(s.replaceAll(':',''),'hex');
function security(akms=[2],wpa=false){
 const oui=wpa?'0050f2':'000fac';
 const b=Buffer.concat([Buffer.from([1,0]),bytes(oui+'04'),Buffer.from([1,0]),bytes(oui+'04'),Buffer.from([akms.length,0]),...akms.map(a=>bytes(oui+a.toString(16).padStart(2,'0')))]);
 return wpa?Buffer.concat([Buffer.from([221,b.length+4]),bytes('0050f201'),b]):Buffer.concat([Buffer.from([48,b.length]),b]);
}
function beacon({ssid='Lab',ap=AP,akms=[2],wpa=false}={}){
 const b=Buffer.alloc(36);b[0]=0x80;b.fill(255,4,10);bytes(ap).copy(b,10);bytes(ap).copy(b,16);b.writeUInt16LE(0x11,34);
 const name=Buffer.from(ssid);return Buffer.concat([b,Buffer.from([0,name.length]),name,security(akms,wpa)]);
}
function key(message,{ap=AP,client=CLIENT,replay=message>=3?8n:7n,nonce=message===4?0:message===2?0x22:0x11,mic=message===1?0:0x33,version=2,akms=[2],qos=false,ht=false,wpa=false}={}){
 const fromAP=message===1||message===3,h=24+(qos?2:0)+(ht?4:0),header=Buffer.alloc(h);
 header[0]=qos?0x88:8;header[1]=(fromAP?2:1)|(ht?128:0);
 bytes(fromAP?client:ap).copy(header,4);bytes(fromAP?ap:client).copy(header,10);bytes(ap).copy(header,16);
 const data=message===2?security(akms,wpa):Buffer.alloc(0),e=Buffer.alloc(99+data.length);
 e[0]=2;e[1]=3;e.writeUInt16BE(e.length-4,2);e[4]=wpa?254:2;
 const info=version|8|(fromAP?128:0)|(message!==1?256:0)|(message>=3?512:0)|(message===3?64:0);
 e.writeUInt16BE(info,5);e.writeBigUInt64BE(BigInt(replay),9);e.fill(nonce,17,49);e.fill(mic,81,97);e.writeUInt16BE(data.length,97);data.copy(e,99);
 return Buffer.concat([header,bytes('aaaa03000000888e'),e]);
}
function pcap(frames,{times=[],big=false,nano=false}={}){
 const header=Buffer.alloc(24),w16=(b,v,i)=>big?b.writeUInt16BE(v,i):b.writeUInt16LE(v,i),w32=(b,v,i)=>big?b.writeUInt32BE(v,i):b.writeUInt32LE(v,i);
 w32(header,nano?0xa1b23c4d:0xa1b2c3d4,0);w16(header,2,4);w16(header,4,6);w32(header,1600,16);w32(header,105,20);
 return Buffer.concat([header,...frames.map((f,i)=>{const r=Buffer.alloc(16),time=times[i]??1000000+i*20000;w32(r,Math.floor(time/1e6),0);w32(r,(time%1e6)*(nano?1000:1),4);w32(r,f.length,8);w32(r,f.length,12);return Buffer.concat([r,f])})]);
}
module.exports={AP,CLIENT,beacon,key,pcap,security};
