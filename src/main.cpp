#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <esp_wifi.h>
#include <esp_timer.h>
#include <atomic>
#include "packet.h"
#include "web_asset.h"

// US channels by default. Change the country and range together for your region.
constexpr uint8_t FIRST_CHANNEL = 1, CHANNEL_COUNT = 11;
constexpr size_t MAX_CAPTURE_BYTES = 256 * 1024, MAX_FILES = 6;
constexpr uint32_t MIN_SECONDS = 15, MAX_SECONDS = 300;
struct Frame { uint64_t us; uint16_t length; uint8_t message; uint8_t data[specter::SNAPLEN]; };
struct Network { String ssid, bssid, security; int channel, rssi; uint8_t mac[6]; };
Network networks[64];
size_t networkCount = 0;
WebServer server(80);
DNSServer dns;
QueueHandle_t queue;
File capture;
String apName, apPassword, apiKey, lastError, captureId, captureSsid, captureBssid;
bool fsReady = false, scanning = false, pending = false, running = false;
uint32_t scanStarted = 0, scanFinished = 0, beginAt = 0, deadline = 0, duration = 60;
uint32_t packetCount = 0, eapolCount = 0, messages[4] = {}, beaconSavedAt = 0;
uint32_t captureBytes = 0;
uint64_t captureStart = 0;
uint8_t target[6] = {}, targetChannel = 1;
std::atomic<bool> accepting{false};
std::atomic<uint32_t> dropped{0};
portMUX_TYPE rxMux = portMUX_INITIALIZER_UNLOCKED;

String quote(const String& s) {
    String out = "\"";
    for (size_t i = 0; i < s.length(); ++i) {
        uint8_t c = s[i];
        if (c == '"' || c == '\\') { out += '\\'; out += char(c); }
        else if (c < 32 || c >= 127) { char b[7]; snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
        else out += char(c);
    }
    return out + '"';
}
String hexRandom() { char s[17]; snprintf(s, sizeof(s), "%08lx%08lx", (unsigned long)esp_random(), (unsigned long)esp_random()); return s; }
String securityName(wifi_auth_mode_t mode) {
    switch (mode) {
        case WIFI_AUTH_OPEN: return "OPEN";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-EAP";
        case WIFI_AUTH_WPA3_PSK: return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
        default: return "OTHER";
    }
}
void json(int code, const String& body) {
    server.sendHeader("Cache-Control", "no-store");
    server.sendHeader("X-Content-Type-Options", "nosniff");
    server.send(code, "application/json", body);
}
void error(int code, const String& message) { json(code, "{\"error\":" + quote(message) + "}"); }
bool mutationAllowed() {
    if (server.header("X-Specter-Key") != apiKey) { error(403, "Reload the dashboard and try again."); return false; }
    if (running || pending || scanning) { error(409, "Radio is busy."); return false; }
    return true;
}
bool validId(const String& id) {
    if (id.length() != 16) return false;
    for (char c : id) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
size_t fileCount() {
    if (!fsReady) return 0;
    size_t count = 0;
    File root = LittleFS.open("/");
    for (File f = root.openNextFile(); f; f = root.openNextFile()) if (String(f.name()).endsWith(".pcap")) ++count;
    return count;
}
bool setCountry() {
    wifi_country_t country = {};
    memcpy(country.cc, "US", 3);
    country.schan = FIRST_CHANNEL; country.nchan = CHANNEL_COUNT;
    country.max_tx_power = 20; country.policy = WIFI_COUNTRY_POLICY_MANUAL;
    return esp_wifi_set_country(&country) == ESP_OK;
}
bool startHotspot() {
    bool ok = WiFi.mode(WIFI_AP_STA);
    WiFi.setAutoReconnect(false);
    WiFi.disconnect(false, false);
    ok = setCountry() && ok;
    ok = WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0)) && ok;
    ok = WiFi.softAP(apName.c_str(), apPassword.c_str(), 1, false, 2) && ok;
    WiFi.setSleep(false);
    dns.start(53, "*", WiFi.softAPIP());
    server.begin();
    if (!ok) lastError = "Hotspot setup failed; restart the board and inspect serial output.";
    return ok;
}

// Wi-Fi task: bounded parsing and zero-wait queue only; never touch flash or HTTP.
void receive(void* buffer, wifi_promiscuous_pkt_type_t type) {
    if (!accepting.load() || (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT)) return;
    auto* pkt = static_cast<wifi_promiscuous_pkt_t*>(buffer);
    if (pkt->rx_ctrl.rx_state || pkt->rx_ctrl.sig_len < 4) return;
    const size_t n = pkt->rx_ctrl.sig_len - 4; // ESP-IDF length includes FCS
    if (n > specter::SNAPLEN) return;
    const auto parsed = specter::parse(pkt->payload, n, target);
    if (parsed.kind == specter::Kind::Ignore) return;
    portENTER_CRITICAL(&rxMux);
    if (!accepting.load()) { portEXIT_CRITICAL(&rxMux); return; }
    const uint32_t now = millis();
    if (parsed.kind == specter::Kind::Beacon && beaconSavedAt && now - beaconSavedAt < 1000) {
        portEXIT_CRITICAL(&rxMux); return;
    }
    Frame frame;
    frame.us = esp_timer_get_time() - captureStart;
    frame.length = n; frame.message = parsed.kind == specter::Kind::Beacon ? 255 : parsed.message;
    memcpy(frame.data, pkt->payload, n);
    if (xQueueSend(queue, &frame, 0) != pdTRUE) dropped.fetch_add(1);
    else if (parsed.kind == specter::Kind::Beacon) beaconSavedAt = now;
    portEXIT_CRITICAL(&rxMux);
}
String summary(const String& reason) {
    String s = "{\"id\":" + quote(captureId) + ",\"ssid\":" + quote(captureSsid) + ",\"bssid\":" + quote(captureBssid);
    s += ",\"channel\":" + String(targetChannel) + ",\"bytes\":" + String(captureBytes);
    s += ",\"packets\":" + String(packetCount) + ",\"eapol\":" + String(eapolCount);
    s += ",\"dropped\":" + String(dropped.load()) + ",\"messages\":[";
    for (int i = 0; i < 4; ++i) { if (i) s += ','; s += String(messages[i]); }
    s += "],\"reason\":" + quote(reason) + ",\"seconds\":" + String((uint32_t)((esp_timer_get_time() - captureStart) / 1000000)) + "}";
    return s;
}
bool writeFrame(const Frame& f) {
    if (captureBytes + 16 + f.length > MAX_CAPTURE_BYTES) { lastError = "Capture reached the 256 KiB limit."; return false; }
    uint8_t header[16]; specter::recordHeader(header, f.us, f.length);
    // Keep the preallocated storage headroom; detect both short writes.
    if (capture.write(header, 16) != 16 || capture.write(f.data, f.length) != f.length) {
        lastError = "Storage write failed; the last PCAP record may be incomplete."; return false;
    }
    captureBytes += 16 + f.length; ++packetCount;
    if (f.message != 255) ++eapolCount;
    if (f.message >= 1 && f.message <= 4) ++messages[f.message - 1];
    return true;
}
void finishCapture(String reason, bool drain = true) {
    // Gate the producer under the same lock before draining its last frames.
    portENTER_CRITICAL(&rxMux); accepting.store(false); portEXIT_CRITICAL(&rxMux);
    esp_wifi_set_promiscuous(false);
    if (!drain) xQueueReset(queue);
    Frame frame;
    while (xQueueReceive(queue, &frame, 0) == pdTRUE) {
        if (!writeFrame(frame)) { reason = lastError; xQueueReset(queue); break; }
    }
    capture.flush(); capture.close();
    String temp = "/" + captureId + ".tmp";
    File meta = LittleFS.open(temp, "w");
    String body = summary(reason);
    bool saved = meta && meta.print(body) == body.length();
    meta.close();
    if (!saved || !LittleFS.rename(temp, "/" + captureId + ".json")) lastError = "Could not save capture summary; PCAP is still available.";
    running = false; pending = false;
    startHotspot();
    Serial.println("Capture ended: " + reason);
}
void beginCapture() {
    pending = false; running = true;
    dns.stop(); server.stop(); WiFi.softAPdisconnect(true);
    bool ok = WiFi.mode(WIFI_STA);
    WiFi.disconnect(false, false); WiFi.setSleep(false);
    ok = setCountry() && ok;
    ok = esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE) == ESP_OK && ok;
    wifi_promiscuous_filter_t filter = {};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    ok = esp_wifi_set_promiscuous_filter(&filter) == ESP_OK && ok;
    ok = esp_wifi_set_promiscuous_rx_cb(receive) == ESP_OK && ok;
    captureStart = esp_timer_get_time(); deadline = millis() + duration * 1000;
    accepting.store(ok);
    if (!ok || esp_wifi_set_promiscuous(true) != ESP_OK) {
        lastError = "Could not start the radio capture."; finishCapture(lastError);
    }
}
void requestCapture() {
    if (!mutationAllowed()) return;
    if (!fsReady || !queue) { error(503, "Capture storage or memory is unavailable."); return; }
    const String seconds = server.arg("seconds");
    if (seconds.isEmpty() || seconds.length() > 3) { error(400, "Duration must be 15–300 seconds."); return; }
    for (char c : seconds) if (c < '0' || c > '9') { error(400, "Invalid duration."); return; }
    duration = seconds.toInt();
    if (duration < MIN_SECONDS || duration > MAX_SECONDS) { error(400, "Duration must be 15–300 seconds."); return; }
    Network* selected = nullptr;
    for (size_t i = 0; i < networkCount; ++i) if (networks[i].bssid == server.arg("bssid")) selected = &networks[i];
    if (!selected) { error(400, "Select a network from the scan results."); return; }
    if (fileCount() >= MAX_FILES || LittleFS.totalBytes() - LittleFS.usedBytes() < MAX_CAPTURE_BYTES + 8192) {
        error(507, "Storage full. Download and delete an older capture first."); return;
    }
    captureId = hexRandom(); captureSsid = selected->ssid; captureBssid = selected->bssid;
    targetChannel = selected->channel; memcpy(target, selected->mac, 6);
    capture = LittleFS.open("/" + captureId + ".pcap", "w");
    uint8_t header[24]; specter::pcapHeader(header);
    if (!capture || capture.write(header, 24) != 24) {
        capture.close(); LittleFS.remove("/" + captureId + ".pcap"); error(507, "Cannot create capture file."); return;
    }
    captureBytes = 24; packetCount = eapolCount = beaconSavedAt = 0;
    memset(messages, 0, sizeof(messages)); dropped.store(0); xQueueReset(queue); lastError = "";
    captureStart = esp_timer_get_time();
    pending = true; beginAt = millis() + 1800;
    json(202, "{\"id\":" + quote(captureId) + ",\"seconds\":" + String(duration) + "}");
}
void requestScan() {
    if (!mutationAllowed()) return;
    WiFi.scanDelete(); lastError = "";
    // Passive scan: wait for beacons, include hidden SSIDs; no probe requests.
    const int result = WiFi.scanNetworks(true, true, true, 300);
    if (result == WIFI_SCAN_FAILED) { error(503, "Scan could not start."); return; }
    scanning = true; scanStarted = millis(); json(202, "{\"scanning\":true}");
}
void pollScan() {
    int count = WiFi.scanComplete();
    if (count == WIFI_SCAN_RUNNING) {
        if (millis() - scanStarted > 20000) {
            esp_wifi_scan_stop(); WiFi.scanDelete(); scanning = false; lastError = "Scan timed out. Try again.";
        }
        return;
    }
    scanning = false;
    if (count < 0) { lastError = "Scan failed. Try again."; return; }
    networkCount = 0;
    for (int i = 0; i < count && networkCount < 64; ++i) {
        int channel = WiFi.channel(i);
        if (channel < FIRST_CHANNEL || channel >= FIRST_CHANNEL + CHANNEL_COUNT) continue;
        Network& n = networks[networkCount++];
        n.ssid = WiFi.SSID(i); n.bssid = WiFi.BSSIDstr(i); n.rssi = WiFi.RSSI(i);
        n.channel = channel; n.security = securityName(WiFi.encryptionType(i)); memcpy(n.mac, WiFi.BSSID(i), 6);
    }
    scanFinished = millis(); WiFi.scanDelete();
}
void state() {
    String s; s.reserve(16000);
    s = "{\"name\":" + quote(apName) + ",\"key\":" + quote(apiKey) + ",\"scanning\":" + (scanning ? "true" : "false");
    s += ",\"pending\":" + String(pending ? "true" : "false") + ",\"error\":" + quote(lastError);
    s += ",\"storageReady\":" + String(fsReady ? "true" : "false") + ",\"used\":" + String(fsReady ? LittleFS.usedBytes() : 0);
    s += ",\"total\":" + String(fsReady ? LittleFS.totalBytes() : 0) + ",\"heap\":" + String(ESP.getFreeHeap());
    s += ",\"scanAge\":" + String(scanFinished ? long((millis() - scanFinished) / 1000) : -1L) + ",\"networks\":[";
    for (size_t i = 0; i < networkCount; ++i) {
        if (i) s += ',';
        auto& n = networks[i];
        s += "{\"ssid\":" + quote(n.ssid) + ",\"bssid\":" + quote(n.bssid) + ",\"security\":" + quote(n.security);
        s += ",\"channel\":" + String(n.channel) + ",\"rssi\":" + String(n.rssi) + "}";
    }
    s += "],\"captures\":[";
    if (fsReady) {
        File root = LittleFS.open("/"); bool first = true;
        for (File f = root.openNextFile(); f; f = root.openNextFile()) {
            String name = f.name(); if (!name.endsWith(".pcap")) continue;
            if (name.startsWith("/")) name.remove(0, 1);
            String id = name.substring(0, name.length() - 5); if (!validId(id)) continue;
            if (!first) s += ',';
            first = false;
            File meta = LittleFS.open("/" + id + ".json", "r");
            if (meta && meta.size() > 2 && meta.size() < 2048) s += meta.readString();
            else s += "{\"id\":" + quote(id) + ",\"bytes\":" + String(f.size()) + ",\"reason\":\"Interrupted capture; inspect PCAP\"}";
        }
    }
    s += "]}"; json(200, s);
}
void setup() {
    Serial.begin(115200);
    Preferences prefs; prefs.begin("specter32", false);
    apPassword = prefs.getString("password", "");
    if (apPassword.length() < 12) { apPassword = hexRandom(); prefs.putString("password", apPassword); }
    // Format only on first provisioning. A later mount failure must preserve captures.
    bool provisioned = prefs.getBool("fsReady", false);
    fsReady = LittleFS.begin(false);
    if (!fsReady && !provisioned && LittleFS.format()) fsReady = LittleFS.begin(false);
    if (fsReady && !provisioned) prefs.putBool("fsReady", true);
    prefs.end();
    if (!fsReady) lastError = "Storage mount failed. Captures disabled; inspect serial output.";
    uint64_t mac = ESP.getEfuseMac(); char suffix[7]; snprintf(suffix, sizeof(suffix), "%06lx", (unsigned long)(mac & 0xffffff));
    apName = String("SPECTER-") + suffix; apiKey = hexRandom();
    WiFi.persistent(false);
    queue = xQueueCreate(24, sizeof(Frame));
    if (!queue) lastError = "Capture buffer allocation failed.";
    const char* headers[] = {"X-Specter-Key"}; server.collectHeaders(headers, 1);
    server.on("/", HTTP_GET, [] {
        server.sendHeader("Content-Encoding", "gzip");
        server.sendHeader("Cache-Control", "no-cache");
        server.sendHeader("X-Content-Type-Options", "nosniff");
        server.sendHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
        server.send_P(200, "text/html", reinterpret_cast<const char*>(WEB_ASSET), sizeof(WEB_ASSET));
    });
    server.on("/api/state", HTTP_GET, state);
    server.on("/api/scan", HTTP_POST, requestScan);
    server.on("/api/capture", HTTP_POST, requestCapture);
    server.on("/api/delete", HTTP_POST, [] {
        if (!mutationAllowed()) return;
        String id = server.arg("id");
        if (!validId(id)) { error(400, "Invalid capture ID."); return; }
        if (!LittleFS.remove("/" + id + ".pcap")) { error(404, "Capture not found."); return; }
        LittleFS.remove("/" + id + ".json"); json(200, "{\"ok\":true}");
    });
    server.on("/api/download", HTTP_GET, [] {
        if (pending) { error(409, "Capture is starting."); return; }
        String id = server.arg("id");
        if (!validId(id)) { error(400, "Invalid capture ID."); return; }
        File f = LittleFS.open("/" + id + ".pcap", "r");
        if (!f) { error(404, "Capture not found."); return; }
        server.sendHeader("Content-Disposition", "attachment; filename=\"specter-" + id + ".pcap\"");
        server.sendHeader("Cache-Control", "no-store");
        server.streamFile(f, "application/vnd.tcpdump.pcap");
    });
    server.onNotFound([] { server.sendHeader("Location", "http://192.168.4.1/"); server.send(302, "text/plain", "Open the dashboard"); });
    startHotspot();
    Serial.println("\nSPECTER32 / passive wireless field console");
    Serial.println("Wi-Fi: " + apName + "\nPassword: " + apPassword + "\nDashboard: http://192.168.4.1");
    if (!lastError.isEmpty()) Serial.println(lastError);
}
void loop() {
    if (running) {
        Frame frame;
        for (unsigned i = 0; i < 32 && xQueueReceive(queue, &frame, 0) == pdTRUE; ++i) {
            if (!writeFrame(frame)) { finishCapture(lastError, false); return; }
        }
        if (int32_t(millis() - deadline) >= 0) finishCapture("Timer finished");
    } else {
        dns.processNextRequest(); server.handleClient();
        if (scanning) pollScan();
        if (pending && int32_t(millis() - beginAt) >= 0) beginCapture();
    }
    delay(1);
}
