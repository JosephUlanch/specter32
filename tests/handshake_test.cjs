const assert=require('node:assert/strict');
const {analyze}=require('../web/handshake.js');
const {AP,beacon,key,pcap}=require('./handshake_fixtures.cjs');
let count=0;
function test(name,frames,status,opts){const r=analyze(pcap(frames,opts));assert.equal(r.status,status,name+': '+JSON.stringify(r));count++;return r;}
const b=beacon(),m1=key(1),m2=key(2),m3=key(3),m4=key(4);
test('all four',[b,m1,m2,m3,m4],'complete');
test('M1/M2',[b,m1,m2],'usable');test('M2/M3',[b,m2,m3],'usable');
test('reversed record order',[m4,m3,m2,m1,b],'complete');
test('retries',[b,m1,m1,m2,m2,m3,m4,m4],'complete');
test('QoS HT',[b,...[1,2,3,4].map(m=>key(m,{qos:true,ht:true}))],'complete');
test('only M1',[b,m1],'incomplete');test('beacons only',[b],'none');test('empty',[],'none');
test('unrelated clients',[b,...[1,2,3,4].map(m=>key(m,{client:'a0b0c0d0e0f'+m}))],'incomplete');
test('different AP',[b,m1,key(2,{ap:'203040506070'})],'incomplete');
test('replay mismatch',[b,m1,key(2,{replay:77n})],'incomplete');
test('replay beyond JS safe integer',[b,key(1,{replay:9007199254740992n}),key(2,{replay:9007199254740993n})],'incomplete');
test('no cross-session full claim',[b,m1,m2,key(3,{nonce:0x55}),m4],'usable');
test('M4 replay mismatch',[b,m1,m2,m3,key(4,{replay:10n})],'usable');
test('M4 nonce mismatch',[b,m1,m2,m3,key(4,{nonce:0x55})],'usable');
test('no AP nonce',[b,key(1,{nonce:0}),m2],'incomplete');
test('no client nonce',[b,m1,key(2,{nonce:0})],'incomplete');
test('no client MIC',[b,m1,key(2,{mic:0})],'incomplete');
test('key versions cannot mix',[b,m1,key(2,{version:1})],'incomplete');
test('unknown SSID',[m1,m2],'missing_ssid');test('hidden SSID',[beacon({ssid:''}),m1,m2],'missing_ssid');
test('conflicting SSIDs',[b,beacon({ssid:'Other'}),m1,m2],'missing_ssid');
test('SAE',[beacon({akms:[8]}),m1,key(2,{akms:[8]})],'review');
test('enterprise',[beacon({akms:[1]}),m1,key(2,{akms:[1]})],'review');
test('transition AP PSK client',[beacon({akms:[2,8]}),m1,m2],'usable');
test('transition AP SAE client',[beacon({akms:[2,8]}),m1,key(2,{akms:[8]})],'review');
test('unsupported key version',[b,key(1,{version:0}),key(2,{version:0})],'review');
test('SHA256 PSK',[beacon({akms:[6]}),key(1,{version:3}),key(2,{version:3,akms:[6]})],'usable');
test('WPA1',[beacon({wpa:true}),key(1,{wpa:true,version:1}),key(2,{wpa:true,version:1})],'usable');
test('stale pairs',[b,m1,m2],'incomplete',{times:[0,1000,6000000]});
test('nonce-bearing M4/M1',[b,m1,key(4,{nonce:0x22})],'usable');
test('nonce-bearing M4/M3',[b,m3,key(4,{nonce:0x22})],'usable');
test('zero-nonce M4 is insufficient',[b,m1,m4],'incomplete');
test('big endian',[b,m1,m2],'usable',{big:true});test('nanosecond',[b,m1,m2],'usable',{nano:true});
for(const [name,mutate] of [
 ['protected',p=>p[1]|=0x40],['fragmented',p=>p[22]=1],['A-MSDU',p=>p[24]=128],['relayed source',p=>p[16]^=1]
]){const p=key(2,{qos:true});mutate(p);test(name,[b,m1,p],'incomplete');}
const malformed=Buffer.from(m2);malformed.writeUInt16BE(65535,34);test('truncated EAPOL',[b,m1,malformed],'incomplete');
const invalidTags=Buffer.from(m2);invalidTags[32+100]=255;test('invalid AKM data',[b,m1,invalidTags],'review');
const full=pcap([b,m1,m2,m3,m4]);assert.equal(analyze(full,AP.match(/../g).join(':')).status,'complete');assert.equal(analyze(full,'ff:ff:ff:ff:ff:ff').status,'none');
for(let n=0;n<full.length;n++){const result=analyze(full.subarray(0,n));assert.ok(result.status);if(result.status==='complete')assert.fail('Truncation certified complete at '+n);}
const unsupported=Buffer.from(full);unsupported.writeUInt32LE(127,20);assert.equal(analyze(unsupported).status,'review');
// Seeded fuzz including valid PCAP headers with random bodies; parser must not throw.
let seed=32;const rand=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
for(let i=0;i<5000;i++){const fuzz=Buffer.alloc(rand()%1024);for(let j=0;j<fuzz.length;j++)fuzz[j]=rand()>>>24;if(i%2===0&&fuzz.length>=24)full.copy(fuzz,0,0,24);assert.ok(analyze(fuzz).status);}
console.log(`Handshake analysis: ${count} scenarios, every truncation, binary formats and 5,000 fuzz inputs passed.`);
