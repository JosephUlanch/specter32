const { chromium } = require('playwright');
const fs = require('node:fs');
const http = require('node:http');
const fixtures=require('./handshake_fixtures.cjs');
const assert = require('node:assert/strict');
(async () => {
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH||undefined});
 const context=await browser.newContext({viewport:{width:390,height:844},isMobile:true,hasTouch:true});
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 let scans=0,captures=0,deletes=0,polls=0;
 let pcap=fixtures.pcap([fixtures.beacon(),...[1,2,3,4].map(m=>fixtures.key(m))]);
 const state={name:'SPECTER-7A92CF',key:'test-session-token',scanning:false,pending:false,error:'',storageReady:true,used:87040,total:2031616,heap:147000,scanAge:8,networks:[
 {ssid:'Workshop',bssid:'10:20:30:40:50:60',channel:6,rssi:-42,security:'WPA2'},
 {ssid:'<img src=x onerror=alert(1)>',bssid:'10:20:30:40:50:61',channel:11,rssi:-72,security:'WPA3'},
 {ssid:'',bssid:'10:20:30:40:50:62',channel:1,rssi:-65,security:'WPA2'}],captures:[{id:'123456789abcdef0',ssid:'Workshop',channel:6,bytes:87040,eapol:9,messages:[2,3,2,2],dropped:0,reason:'Timer finished'}]};
 // Real HTTP response: intercepted Playwright downloads can be canceled by Chromium.
 const server=http.createServer(async(req,res)=>{
  const path=new URL(req.url,'http://localhost').pathname;let data={};
  const send=(type,body,headers={})=>{res.writeHead(200,{'Content-Type':type,'Content-Length':Buffer.byteLength(body),...headers});res.end(body)};
  try {
   let body='';for await(const chunk of req)body+=chunk;
   if(path==='/')return send('text/html',fs.readFileSync('web/index.html'));
   if(path==='/handshake.js')return send('application/javascript',fs.readFileSync('web/handshake.js'));
   if(path==='/favicon.ico'){res.writeHead(204);res.end();return;}
   if(path==='/api/state'){polls++;data=state;}
   else if(path==='/api/scan'){scans++;assert.equal(req.headers['x-specter-key'],state.key);await new Promise(r=>setTimeout(r,2600));}
   else if(path==='/api/capture'){captures++;const p=new URLSearchParams(body);assert.equal(p.get('bssid'),state.networks[0].bssid);assert.equal(p.get('seconds'),'30');data={id:'abcdef0123456789',seconds:30};}
   else if(path==='/api/delete'){deletes++;state.captures=[];}
   else if(/^\/captures\/[a-f0-9]{16}\.pcap$/.test(path))return send('application/octet-stream',pcap,{'Content-Disposition':"attachment; filename=\"specter-123456789abcdef0.pcap\"; filename*=UTF-8''specter-123456789abcdef0.pcap",'X-Content-Type-Options':'nosniff'});
   else throw Error(path);
   send('application/json',JSON.stringify(data));
  } catch(e){errors.push(e.message);res.writeHead(500);res.end('Test server error');}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const base=`http://127.0.0.1:${server.address().port}/`;
 await page.goto(base);await page.waitForFunction(()=>document.getElementById('networkCount').textContent==='3');
 assert.equal(await page.locator('#networks img').count(),0);
 await page.getByText('Complete handshake',{exact:true}).waitFor();
 state.networks[1].ssid='Lab guest';await page.waitForFunction(()=>document.getElementById('networks').textContent.includes('Lab guest'));
 assert.equal(await page.locator('#capture').isDisabled(),true);
 await page.getByRole('button',{name:'Select Workshop',exact:true}).click();assert.equal(await page.locator('#capture').isEnabled(),true);
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.screenshot({path:'downloads/dashboard-mobile.png',fullPage:true});
 await page.setViewportSize({width:1440,height:1000});await page.screenshot({path:'downloads/dashboard-desktop.png',fullPage:true});
 const download=page.waitForEvent('download');await page.getByRole('link',{name:'↓ PCAP'}).click();const saved=await download;assert.equal(saved.suggestedFilename(),'specter-123456789abcdef0.pcap');assert.deepEqual(fs.readFileSync(await saved.path()),pcap);assert.equal(page.url(),base);
 // Old aggregate counts remain nonzero: the label must follow actual packets.
 state.captures[0].id='123456789abcdef1';
 pcap=fixtures.pcap([fixtures.beacon(),...[1,2,3,4].map(m=>fixtures.key(m,{client:'a0b0c0d0e0f'+m}))]);
 await page.getByText('Incomplete handshake',{exact:true}).waitFor();
 assert.equal(await page.getByText('Complete handshake',{exact:true}).count(),0);
 state.captures[0].id='123456789abcdef2';pcap=fixtures.pcap([fixtures.beacon()]);
 await page.getByText('No handshake',{exact:true}).waitFor();
 state.captures[0].id='123456789abcdef3';pcap=fixtures.pcap([fixtures.key(1),fixtures.key(2)]);
 await page.getByText('Pair found · SSID needed',{exact:true}).waitFor();
 await page.locator('#scan').click();await page.waitForTimeout(6000);assert.equal(scans,1);assert.ok(polls>=3,'polling must survive a slow action');
 page.on('dialog',d=>d.accept());await page.getByRole('button',{name:'Delete',exact:true}).click();
 await page.waitForFunction(()=>document.getElementById('captureCount').textContent==='0');assert.equal(deletes,1);
 await page.locator('#duration').selectOption('30');await page.locator('#capture').click();
 await page.waitForFunction(()=>!document.getElementById('offline').hidden);assert.equal(captures,1);assert.equal(await page.locator('#scan').isDisabled(),true);
 await page.reload();await page.waitForFunction(()=>!document.getElementById('offline').hidden);
 assert.ok(await page.evaluate(()=>Number(sessionStorage.getItem('specterUntil'))>Date.now()));assert.deepEqual(errors,[]);
 await browser.close();await new Promise(resolve=>server.close(resolve));console.log('Dashboard: mobile/desktop layout, SSID escaping, slow scan polling, selection, download, delete, capture and reload passed.');
})().catch(e=>{console.error(e);process.exit(1)});
