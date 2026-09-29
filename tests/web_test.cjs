const { chromium } = require('playwright');
const fs = require('node:fs');
const assert = require('node:assert/strict');
(async () => {
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH||undefined});
 const context=await browser.newContext({viewport:{width:390,height:844},isMobile:true,hasTouch:true});
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 let scans=0,captures=0,deletes=0,polls=0;
 const state={name:'SPECTER-7A92CF',key:'test-session-token',scanning:false,pending:false,error:'',storageReady:true,used:87040,total:2031616,heap:147000,scanAge:8,networks:[
 {ssid:'Workshop',bssid:'10:20:30:40:50:60',channel:6,rssi:-42,security:'WPA2'},
 {ssid:'<img src=x onerror=alert(1)>',bssid:'10:20:30:40:50:61',channel:11,rssi:-72,security:'WPA3'},
 {ssid:'',bssid:'10:20:30:40:50:62',channel:1,rssi:-65,security:'WPA2'}],captures:[{id:'123456789abcdef0',ssid:'Workshop',channel:6,bytes:87040,eapol:9,messages:[2,3,2,2],dropped:0,reason:'Timer finished'}]};
 await page.route('http://specter.test/**',async route=>{
  const path=new URL(route.request().url()).pathname;let data={};
  if(path==='/')return route.fulfill({contentType:'text/html',body:fs.readFileSync('web/index.html','utf8')});
  if(path==='/api/state'){polls++;data=state;}
  else if(path==='/api/scan'){scans++;assert.equal(route.request().headers()['x-specter-key'],state.key);await new Promise(r=>setTimeout(r,2600));}
  else if(path==='/api/capture'){captures++;const p=new URLSearchParams(route.request().postData());assert.equal(p.get('bssid'),state.networks[0].bssid);assert.equal(p.get('seconds'),'30');data={id:'abcdef0123456789',seconds:30};}
  else if(path==='/api/delete'){deletes++;state.captures=[];}
  else if(path==='/api/download')return route.fulfill({contentType:'application/vnd.tcpdump.pcap',headers:{'Content-Disposition':'attachment; filename="capture.pcap"'},body:Buffer.from([0xd4,0xc3,0xb2,0xa1])});
  else throw Error(path);
  await route.fulfill({contentType:'application/json',body:JSON.stringify(data)});
 });
 await page.goto('http://specter.test/');await page.waitForFunction(()=>document.getElementById('networkCount').textContent==='3');
 assert.equal(await page.locator('#networks img').count(),0);
 state.networks[1].ssid='Lab guest';await page.waitForFunction(()=>document.getElementById('networks').textContent.includes('Lab guest'));
 assert.equal(await page.locator('#capture').isDisabled(),true);
 await page.getByRole('button',{name:'Select Workshop',exact:true}).click();assert.equal(await page.locator('#capture').isEnabled(),true);
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.screenshot({path:'downloads/dashboard-mobile.png',fullPage:true});
 await page.setViewportSize({width:1440,height:1000});await page.screenshot({path:'downloads/dashboard-desktop.png',fullPage:true});
 const download=page.waitForEvent('download');await page.getByRole('link',{name:'↓ PCAP'}).click();assert.match((await download).suggestedFilename(),/\.pcap$/);
 await page.locator('#scan').click();await page.waitForTimeout(6000);assert.equal(scans,1);assert.ok(polls>=3,'polling must survive a slow action');
 page.on('dialog',d=>d.accept());await page.getByRole('button',{name:'Delete',exact:true}).click();
 await page.waitForFunction(()=>document.getElementById('captureCount').textContent==='0');assert.equal(deletes,1);
 await page.locator('#duration').selectOption('30');await page.locator('#capture').click();
 await page.waitForFunction(()=>!document.getElementById('offline').hidden);assert.equal(captures,1);assert.equal(await page.locator('#scan').isDisabled(),true);
 await page.reload();await page.waitForFunction(()=>!document.getElementById('offline').hidden);
 assert.ok(await page.evaluate(()=>Number(sessionStorage.getItem('specterUntil'))>Date.now()));assert.deepEqual(errors,[]);
 await browser.close();console.log('Dashboard: mobile/desktop layout, SSID escaping, slow scan polling, selection, download, delete, capture and reload passed.');
})().catch(e=>{console.error(e);process.exit(1)});
