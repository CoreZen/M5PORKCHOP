// pwncrack.org hash-cracking sync client
// Uploads .hc22000 captures; downloads potfile of cracked results

#include "pwncrack.h"
#include "../core/sd_layout.h"
#include "../core/config.h"
#include "../core/heap_gates.h"
#include "../core/tls.h"
#include "../core/wifi_utils.h"
#include "../piglet/mood.h"
#include <SD.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <ctype.h>
#include <esp_heap_caps.h>
#include <algorithm>

// pwncrack.org API
static const char* PWNCRACK_HOST        = "pwncrack.org";
static const uint16_t PWNCRACK_PORT     = 443;
static const char* PWNCRACK_UPLOAD_PATH = "/upload_handshake";
static const size_t PWNCRACK_MAX_CACHE_ENTRIES = 500;

// Static member initialization
bool Pwncrack::cacheLoaded = false;
char Pwncrack::lastError[64] = "";
std::vector<Pwncrack::CrackedEntry> Pwncrack::crackedCache;
std::vector<Pwncrack::UploadedEntry> Pwncrack::uploadedCache;
volatile bool Pwncrack::busy = false;
bool Pwncrack::batchMode = false;

bool Pwncrack::isBusy() {
    return busy;
}

void Pwncrack::normalizeBSSID_Char(const char* bssid, char* output, size_t outLen) {
    if (!bssid || !output || outLen < 1) return;
    size_t outIdx = 0;
    for (int i = 0; bssid[i] && outIdx < outLen - 1; i++) {
        char c = bssid[i];
        if (c != ':' && c != '-') {
            output[outIdx++] = (char)toupper(c);
        }
    }
    output[outIdx] = '\0';
}

// ============================================================================
// Cache Management (disk only)
// ============================================================================

bool Pwncrack::loadUploadedList() {
    uploadedCache.clear();
    uploadedCache.reserve(64);  // 64 * 48B = 3KB — avoids reallocations
    const char* uploadedPath = SDLayout::pwncrackUploadedPath();
    if (!SD.exists(uploadedPath)) return true;

    File f = SD.open(uploadedPath, FILE_READ);
    if (!f) {
        strncpy(lastError, "CANNOT OPEN UPLOADED", sizeof(lastError) - 1);
        lastError[sizeof(lastError) - 1] = '\0';
        return false;
    }

    char lineBuf[64];
    while (f.available() && uploadedCache.size() < PWNCRACK_MAX_CACHE_ENTRIES) {
        size_t len = f.readBytesUntil('\n', lineBuf, sizeof(lineBuf) - 1);
        lineBuf[len] = '\0';
        // Trim trailing whitespace
        while (len > 0 && (lineBuf[len - 1] == '\r' || lineBuf[len - 1] == ' ')) {
            lineBuf[--len] = '\0';
        }
        if (len == 0) continue;

        UploadedEntry entry;
        strncpy(entry.filename, lineBuf, sizeof(entry.filename) - 1);
        entry.filename[sizeof(entry.filename) - 1] = '\0';
        if (entry.filename[0] != '\0') {
            uploadedCache.push_back(entry);
        }
    }

    f.close();
    // Sort for binary search — O(n log n) once, enables O(log n) lookups
    std::sort(uploadedCache.begin(), uploadedCache.end(),
        [](const UploadedEntry& a, const UploadedEntry& b) {
            return strcmp(a.filename, b.filename) < 0;
        });
    return true;
}

bool Pwncrack::loadCache() {
    if (cacheLoaded) return true;

    crackedCache.clear();
    crackedCache.reserve(8);
    uploadedCache.clear();

    const char* cachePath = SDLayout::pwncrackResultsPath();
    if (SD.exists(cachePath)) {
        File f = SD.open(cachePath, FILE_READ);
        if (!f) {
            strncpy(lastError, "CANNOT OPEN CACHE", sizeof(lastError) - 1);
            lastError[sizeof(lastError) - 1] = '\0';
            return false;
        }

        // pwncrack potfile format: HASH:BSSID:CLIENTMAC:ESSID:PASSWORD (colon-delimited)
        // Example: bfdf...e007:48ee0c3e55c9:4a7b02a49a5c:Sarit2:hunter2
        // BSSID is the 2nd field; password is everything after the 4th colon (may contain colons)
        char lineBuf[160];
        while (f.available() && crackedCache.size() < PWNCRACK_MAX_CACHE_ENTRIES) {
            size_t len = f.readBytesUntil('\n', lineBuf, sizeof(lineBuf) - 1);
            lineBuf[len] = '\0';
            // Trim trailing whitespace
            while (len > 0 && (lineBuf[len - 1] == '\r' || lineBuf[len - 1] == ' ')) {
                lineBuf[--len] = '\0';
            }
            if (len < 10) continue;

            // Locate the first four colons. BSSID is the 2nd field (between c1 and
            // c2); password is everything after the 4th colon (it may contain colons).
            const char* c1 = strchr(lineBuf, ':');
            const char* c2 = c1 ? strchr(c1 + 1, ':') : nullptr;
            const char* c3 = c2 ? strchr(c2 + 1, ':') : nullptr;
            const char* c4 = c3 ? strchr(c3 + 1, ':') : nullptr;
            if (!c4) continue;

            size_t apLen = (size_t)(c2 - (c1 + 1));
            if (apLen < 12 || apLen > 17) continue;  // sanity: bare hex or colon-notated BSSID

            const char* pwStart = c4 + 1;
            if (pwStart[0] == '\0') continue;

            CrackedEntry entry;
            memset(&entry, 0, sizeof(entry));

            // Copy BSSID field and normalize
            char rawAp[18];
            size_t copyLen = apLen < sizeof(rawAp) - 1 ? apLen : sizeof(rawAp) - 1;
            memcpy(rawAp, c1 + 1, copyLen);
            rawAp[copyLen] = '\0';
            normalizeBSSID_Char(rawAp, entry.bssid, sizeof(entry.bssid));
            if (entry.bssid[0] == '\0') continue;

            size_t pwLen = strlen(pwStart);
            if (pwLen >= sizeof(entry.password)) pwLen = sizeof(entry.password) - 1;
            memcpy(entry.password, pwStart, pwLen);
            entry.password[pwLen] = '\0';

            crackedCache.push_back(entry);
        }

        f.close();
    }

    // Sort for binary search — O(n log n) once, enables O(log n) lookups
    std::sort(crackedCache.begin(), crackedCache.end(),
        [](const CrackedEntry& a, const CrackedEntry& b) {
            return strcmp(a.bssid, b.bssid) < 0;
        });

    if (!loadUploadedList()) {
        return false;
    }

    cacheLoaded = true;
    return true;
}

// ============================================================================
// Local Cache Queries
// ============================================================================

const Pwncrack::CrackedEntry* Pwncrack::findCracked(const char* normalizedBssid) {
    auto it = std::lower_bound(crackedCache.begin(), crackedCache.end(), normalizedBssid,
        [](const CrackedEntry& entry, const char* bssid) {
            return strcmp(entry.bssid, bssid) < 0;
        });
    if (it != crackedCache.end() && strcmp(it->bssid, normalizedBssid) == 0) {
        return &(*it);
    }
    return nullptr;
}

bool Pwncrack::findUploaded(const char* filename) {
    auto it = std::lower_bound(uploadedCache.begin(), uploadedCache.end(), filename,
        [](const UploadedEntry& entry, const char* fn) {
            return strcmp(entry.filename, fn) < 0;
        });
    return it != uploadedCache.end() && strcmp(it->filename, filename) == 0;
}

bool Pwncrack::isCracked(const char* bssid) {
    loadCache();
    char key[13];
    normalizeBSSID_Char(bssid, key, sizeof(key));
    return findCracked(key) != nullptr;
}

const char* Pwncrack::getPassword(const char* bssid) {
    loadCache();
    char key[13];
    normalizeBSSID_Char(bssid, key, sizeof(key));
    const CrackedEntry* entry = findCracked(key);
    return entry ? entry->password : "";
}

uint16_t Pwncrack::getCrackedCount() {
    loadCache();
    return crackedCache.size();
}

bool Pwncrack::isUploaded(const char* filename) {
    loadCache();
    return findUploaded(filename);
}

const char* Pwncrack::getLastError() {
    return lastError;
}

void Pwncrack::freeCacheMemory() {
    size_t crackedCount = crackedCache.size();
    size_t uploadedCount = uploadedCache.size();
    crackedCache.clear();
    crackedCache.shrink_to_fit();
    uploadedCache.clear();
    uploadedCache.shrink_to_fit();
    cacheLoaded = false;
    Serial.printf("[PWNCRACK] Freed cache: %u cracked, %u uploaded\n",
                  (unsigned int)crackedCount, (unsigned int)uploadedCount);
}

bool Pwncrack::saveUploadedList() {
    const char* uploadedPath = SDLayout::pwncrackUploadedPath();
    File f = SD.open(uploadedPath, FILE_WRITE);
    if (!f) {
        strncpy(lastError, "CANNOT WRITE UPLOADED", sizeof(lastError) - 1);
        lastError[sizeof(lastError) - 1] = '\0';
        return false;
    }

    for (size_t i = 0; i < uploadedCache.size(); i++) {
        f.println(uploadedCache[i].filename);
    }

    f.close();
    return true;
}

void Pwncrack::markAsUploaded(const char* filename) {
    loadCache();
    if (!filename || filename[0] == '\0') return;

    // Sorted insertion — maintains O(log n) lookup invariant
    auto it = std::lower_bound(uploadedCache.begin(), uploadedCache.end(), filename,
        [](const UploadedEntry& e, const char* fn) { return strcmp(e.filename, fn) < 0; });
    if (it != uploadedCache.end() && strcmp(it->filename, filename) == 0) return;
    if (uploadedCache.size() >= PWNCRACK_MAX_CACHE_ENTRIES) return;

    UploadedEntry entry;
    strncpy(entry.filename, filename, sizeof(entry.filename) - 1);
    entry.filename[sizeof(entry.filename) - 1] = '\0';
    uploadedCache.insert(it, entry);
    if (!batchMode) {
        saveUploadedList();
    }
}

void Pwncrack::beginBatchUpload() {
    batchMode = true;
}

void Pwncrack::endBatchUpload() {
    if (batchMode) {
        batchMode = false;
        saveUploadedList();
        Serial.println("[PWNCRACK] Batch upload complete, saved uploaded list");
    }
}

// ============================================================================
// Network Operations
// ============================================================================

bool Pwncrack::hasApiKey() {
    const char* key = Config::wifi().pwncrackKey;
    if (!key || key[0] == '\0') return false;
    // pwncrack keys are hex strings; accept any non-empty string of printable chars
    size_t len = strlen(key);
    if (len < 8 || len > 64) return false;
    return true;
}

bool Pwncrack::canSync() {
    // Free caches to maximize available heap
    freeCacheMemory();

    HeapGates::TlsGateStatus tls = HeapGates::checkTlsGates();

    Serial.printf("[PWNCRACK] canSync: %u free, %u contiguous (need %u/%u)\n",
                  (unsigned int)tls.freeHeap, (unsigned int)tls.largestBlock,
                  (unsigned int)HeapPolicy::kMinHeapForTls,
                  (unsigned int)HeapPolicy::kMinContigForTls);

    return HeapGates::canTls(tls, lastError, sizeof(lastError));
}

bool Pwncrack::uploadSingleCapture(const char* filepath, const char* filename22000) {
    if (!filepath || !filename22000) return false;

    Serial.printf("[PWNCRACK] Uploading: %s\n", filepath);

    // Check file exists and get size
    File capFile = SD.open(filepath, FILE_READ);
    if (!capFile) {
        Serial.printf("[PWNCRACK] Cannot open file: %s\n", filepath);
        return false;
    }
    size_t fileSize = capFile.size();
    if (fileSize == 0 || fileSize > 100000) {  // Max 100KB
        capFile.close();
        Serial.printf("[PWNCRACK] Invalid file size: %u\n", (unsigned int)fileSize);
        return false;
    }

    // Create WiFiClientSecure with minimal buffers
    WiFiClientSecure client;
    client.setInsecure();  // Skip cert validation — saves ~10KB heap

    // Connect with timeout
    Serial.printf("[PWNCRACK] Connecting to %s:%d\n", PWNCRACK_HOST, PWNCRACK_PORT);
    if (!client.connect(PWNCRACK_HOST, PWNCRACK_PORT, 15000)) {
        capFile.close();
        char tlsErr[64] = {0};
        int errCode = client.lastError(tlsErr, sizeof(tlsErr) - 1);
        snprintf(lastError, sizeof(lastError), "TLS CONNECT: %d", errCode);
        Serial.printf("[PWNCRACK] TLS connect failed: err=%d (%s)\n", errCode, tlsErr);
        return false;
    }

    // Build multipart boundary
    char boundary[32];
    snprintf(boundary, sizeof(boundary), "----PCrack%08lX", millis());

    const char* apiKey = Config::wifi().pwncrackKey;

    // Compute Content-Length over TWO multipart parts:
    //
    // Part 1 — key field:
    //   --boundary\r\n
    //   Content-Disposition: form-data; name="key"\r\n
    //   \r\n
    //   <key value>
    //   \r\n
    //
    // Part 2 — handshake file:
    //   --boundary\r\n
    //   Content-Disposition: form-data; name="handshake"; filename="<name>.hc22000"\r\n
    //   Content-Type: application/octet-stream\r\n
    //   \r\n
    //   <file data>
    //   \r\n
    //
    // Epilogue:
    //   --boundary--\r\n

    char keyDisp[80];
    snprintf(keyDisp, sizeof(keyDisp),
             "Content-Disposition: form-data; name=\"key\"");

    char fileDisp[128];
    snprintf(fileDisp, sizeof(fileDisp),
             "Content-Disposition: form-data; name=\"handshake\"; filename=\"%s\"",
             filename22000);

    size_t boundaryLen = strlen(boundary);
    size_t keyLen = strlen(apiKey);
    size_t keyDispLen = strlen(keyDisp);
    size_t fileDispLen = strlen(fileDisp);

    // Part 1: --boundary\r\n + keyDisp\r\n + \r\n + key + \r\n
    size_t part1 = 2 + boundaryLen + 2 +   // --boundary\r\n
                   keyDispLen + 2 +          // keyDisp\r\n
                   2 +                       // \r\n (blank line)
                   keyLen +                  // key value
                   2;                        // \r\n

    // Part 2: --boundary\r\n + fileDisp\r\n + Content-Type\r\n + \r\n + fileData + \r\n
    size_t part2 = 2 + boundaryLen + 2 +    // --boundary\r\n
                   fileDispLen + 2 +         // fileDisp\r\n
                   38 + 2 +                  // Content-Type: application/octet-stream\r\n
                   2 +                       // \r\n (blank line)
                   fileSize +               // file data
                   2;                        // \r\n

    // Epilogue: --boundary--\r\n
    size_t epilogue = 2 + boundaryLen + 4;   // --boundary--\r\n

    size_t contentLength = part1 + part2 + epilogue;

    // Send HTTP headers
    client.printf("POST %s HTTP/1.1\r\n", PWNCRACK_UPLOAD_PATH);
    client.printf("Host: %s\r\n", PWNCRACK_HOST);
    client.printf("Content-Type: multipart/form-data; boundary=%s\r\n", boundary);
    client.printf("Content-Length: %u\r\n", (unsigned int)contentLength);
    client.print("Connection: close\r\n\r\n");

    // Part 1: key field
    client.printf("--%s\r\n", boundary);
    client.printf("%s\r\n", keyDisp);
    client.print("\r\n");
    client.print(apiKey);
    client.print("\r\n");

    // Part 2: handshake file
    client.printf("--%s\r\n", boundary);
    client.printf("%s\r\n", fileDisp);
    client.print("Content-Type: application/octet-stream\r\n\r\n");

    // Stream the file with heap pacing (shared TLS uploader). On failure it has
    // already closed the file and stopped the client.
    client.setTimeout(30000);
    if (!Tls::streamFile(client, capFile, fileSize, "PWNCRACK", lastError, sizeof(lastError))) {
        return false;
    }

    if (!client.connected()) {
        snprintf(lastError, sizeof(lastError), "Connection lost during upload");
        return false;
    }

    // Flush upload data before sending epilogue
    client.flush();

    // End multipart
    client.printf("\r\n--%s--\r\n", boundary);

    // Read response (check status code)
    unsigned long timeout = millis() + 10000;
    while (client.connected() && !client.available() && millis() < timeout) {
        delay(10);
        yield();
    }

    bool success = false;
    if (client.available()) {
        char response[64];
        size_t len = client.readBytesUntil('\n', response, sizeof(response) - 1);
        response[len] = '\0';
        Serial.printf("[PWNCRACK] Response: %s\n", response);

        if (strstr(response, "200") || strstr(response, "201")) {
            success = true;
        } else if (strstr(response, "409")) {
            // Already uploaded — treat as success
            success = true;
            Serial.println("[PWNCRACK] Already uploaded (409)");
        }
    }

    client.stop();

    if (success) {
        Serial.printf("[PWNCRACK] Upload success: %s\n", filename22000);
    } else {
        if (lastError[0] == '\0') {
            strncpy(lastError, "UPLOAD REJECTED", sizeof(lastError) - 1);
        }
        Serial.printf("[PWNCRACK] Upload error: %s (heap=%u largest=%u)\n",
                      lastError, (unsigned)ESP.getFreeHeap(),
                      (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
    }

    return success;
}

bool Pwncrack::downloadPotfile(uint16_t& newCracks) {
    newCracks = 0;

    Serial.println("[PWNCRACK] Downloading potfile...");

    WiFiClientSecure client;
    client.setInsecure();

    if (!client.connect(PWNCRACK_HOST, PWNCRACK_PORT, 15000)) {
        char tlsErr[64] = {0};
        int errCode = client.lastError(tlsErr, sizeof(tlsErr) - 1);
        snprintf(lastError, sizeof(lastError), "POTFILE TLS: %d", errCode);
        Serial.printf("[PWNCRACK] Potfile TLS failed: err=%d (%s)\n", errCode, tlsErr);
        return false;
    }

    // GET /download_potfile_script?key=<apikey>
    client.printf("GET /download_potfile_script?key=%s HTTP/1.1\r\n", Config::wifi().pwncrackKey);
    client.printf("Host: %s\r\n", PWNCRACK_HOST);
    client.print("Connection: close\r\n\r\n");

    unsigned long timeout = millis() + 15000;
    while (client.connected() && !client.available() && millis() < timeout) {
        delay(10);
        yield();
    }

    if (!client.available()) {
        client.stop();
        strncpy(lastError, "POTFILE TIMEOUT", sizeof(lastError) - 1);
        return false;
    }

    // Skip HTTP headers
    bool headersEnded = false;
    char headerLine[128];
    while (client.connected() && client.available() && !headersEnded) {
        size_t len = client.readBytesUntil('\n', headerLine, sizeof(headerLine) - 1);
        headerLine[len] = '\0';
        if (len <= 1 || (len == 1 && headerLine[0] == '\r')) {
            headersEnded = true;
        }
    }

    if (!headersEnded) {
        client.stop();
        strncpy(lastError, "POTFILE BAD RESPONSE", sizeof(lastError) - 1);
        return false;
    }

    // Open cache file for writing (overwrite)
    const char* cachePath = SDLayout::pwncrackResultsPath();
    File cacheFile = SD.open(cachePath, FILE_WRITE);
    if (!cacheFile) {
        client.stop();
        strncpy(lastError, "CANNOT WRITE CACHE", sizeof(lastError) - 1);
        return false;
    }

    // Stream potfile line-by-line directly to SD
    // Format: ...:AP:Pass (colon-delimited, AP is 2nd-to-last, Pass is last)
    char lineBuf[160];
    uint16_t lineCount = 0;

    while (client.connected() || client.available()) {
        if (client.available()) {
            size_t len = client.readBytesUntil('\n', lineBuf, sizeof(lineBuf) - 1);
            if (len > 0) {
                lineBuf[len] = '\0';
                // Trim \r if present
                if (len > 0 && lineBuf[len - 1] == '\r') {
                    lineBuf[len - 1] = '\0';
                }

                // Validate: needs at least two colons (AP and Pass fields)
                int colonCount = 0;
                for (size_t i = 0; lineBuf[i]; i++) {
                    if (lineBuf[i] == ':') colonCount++;
                }

                if (colonCount >= 2 && strlen(lineBuf) > 5) {
                    cacheFile.println(lineBuf);
                    lineCount++;
                }
            }
        } else {
            delay(10);
        }

        // Safety timeout
        if (millis() > timeout + 30000) {
            Serial.println("[PWNCRACK] Potfile download timeout");
            break;
        }

        yield();
    }

    cacheFile.close();
    client.stop();

    Serial.printf("[PWNCRACK] Potfile downloaded: %u entries\n", (unsigned int)lineCount);
    newCracks = lineCount;

    return true;
}

PwncrackSyncResult Pwncrack::syncCaptures(PwncrackProgressCallback cb) {
    PwncrackSyncResult result = {};
    result.success = false;
    result.error[0] = '\0';

    busy = true;

    // Pre-flight checks
    if (!hasApiKey()) {
        strncpy(result.error, "NO PWNCRACK KEY", sizeof(result.error) - 1);
        busy = false;
        return result;
    }

    if (WiFi.status() != WL_CONNECTED) {
        strncpy(result.error, "WIFI NOT CONNECTED", sizeof(result.error) - 1);
        busy = false;
        return result;
    }

    if (cb) cb("prepping heap", 0, 0);

    // Proactive heap conditioning
    HeapGates::TlsGateStatus tls = HeapGates::checkTlsGates();
    if (HeapGates::shouldProactivelyCondition(tls)) {
        if (cb) cb("OPTIMIZING HEAP", 0, 0);
        Serial.printf("[PWNCRACK] Proactive conditioning: %u < %u threshold\n",
                      (unsigned int)tls.largestBlock,
                      (unsigned int)HeapPolicy::kProactiveTlsConditioning);
        WiFiUtils::conditionHeapForTLS();
    }

    // Check heap is sufficient for TLS operations
    if (!canSync()) {
        if (cb) cb("CONDITIONING HEAP", 0, 0);
        Serial.println("[PWNCRACK] Heap insufficient, attempting conditioning...");

        size_t largestAfter = WiFiUtils::conditionHeapForTLS();

        if (!canSync()) {
            Mood::setStatusMessage("HEAP TIGHT - TRY OINK");
            snprintf(result.error, sizeof(result.error),
                     "%s (TRY OINK)", lastError);
            busy = false;
            return result;
        }

        Serial.printf("[PWNCRACK] Conditioning successful: largest=%u\n",
                      (unsigned int)largestAfter);
    }

    // Collect .22000 files to upload from handshakes directory
    if (cb) cb("scanning caps", 0, 0);
    const char* hsDir = SDLayout::handshakesDir();
    if (!SD.exists(hsDir)) {
        strncpy(result.error, "NO HANDSHAKES DIR", sizeof(result.error) - 1);
        busy = false;
        return result;
    }

    // Load uploaded list only (not cracked cache) to keep heap clear before TLS
    loadUploadedList();

    // Collect pending uploads (store paths + filenames temporarily)
    struct PendingUpload {
        char path[80];      // Full SD path to the .22000 file
        char fname22k[48];  // Filename with .hc22000 extension for multipart
        char filename[48];  // Original filename (for uploaded-list tracking)
    };
    static PendingUpload pendingUploads[16];  // Max 16 per sync
    uint8_t pendingCount = 0;

    File dir = SD.open(hsDir);
    if (dir && dir.isDirectory()) {
        File file = dir.openNextFile();
        uint8_t filesScanned = 0;
        while (file && pendingCount < 16) {
            // Yield every 10 files to prevent WDT on large directories
            if (++filesScanned >= 10) {
                filesScanned = 0;
                yield();
            }

            const char* rawName = file.name();
            const char* slash = strrchr(rawName, '/');
            const char* fname = slash ? slash + 1 : rawName;
            size_t fnameLen = strlen(fname);

            // pwncrack only accepts .22000 (PMKID + 4-way) — not raw pcap
            bool is22000 = (fnameLen > 6 && strcmp(fname + fnameLen - 6, ".22000") == 0);

            if (is22000) {
                // Check uploaded list by filename
                if (!findUploaded(fname)) {
                    snprintf(pendingUploads[pendingCount].path,
                             sizeof(pendingUploads[pendingCount].path),
                             "%s/%s", hsDir, fname);

                    // Store original filename for tracking
                    strncpy(pendingUploads[pendingCount].filename, fname,
                            sizeof(pendingUploads[pendingCount].filename) - 1);
                    pendingUploads[pendingCount].filename[
                        sizeof(pendingUploads[pendingCount].filename) - 1] = '\0';

                    // Build the .hc22000 multipart filename: replace .22000 with .hc22000
                    // (pwncrack validates the upload filename extension must be .hc22000)
                    size_t baseLen = fnameLen - 6;  // strip ".22000"
                    if (baseLen >= sizeof(pendingUploads[pendingCount].fname22k) - 8) {
                        baseLen = sizeof(pendingUploads[pendingCount].fname22k) - 8;
                    }
                    memcpy(pendingUploads[pendingCount].fname22k, fname, baseLen);
                    memcpy(pendingUploads[pendingCount].fname22k + baseLen, ".hc22000", 9);

                    pendingCount++;
                } else {
                    result.skipped++;
                }
            }
            file.close();
            file = dir.openNextFile();
        }
        dir.close();
    }

    Serial.printf("[PWNCRACK] Found %u files to upload, %u skipped\n",
                  (unsigned int)pendingCount, (unsigned int)result.skipped);

    // Free cache before TLS operations
    freeCacheMemory();

    // Track successful uploads with bitmask — mark AFTER all TLS operations
    uint16_t successMask = 0;

    // Upload each pending file
    if (cb) cb("yoinking caps", 0, 0);
    for (uint8_t i = 0; i < pendingCount; i++) {
        if (cb) {
            char status[32];
            snprintf(status, sizeof(status), "UPLOAD %u/%u", i + 1, pendingCount);
            cb(status, i + 1, pendingCount);
        }

        Serial.printf("[PWNCRACK] Heap before upload %u: %u\n",
                      i, (unsigned int)ESP.getFreeHeap());

        // Re-check TLS gates before each upload
        HeapGates::TlsGateStatus tlsPerFile = HeapGates::checkTlsGates();
        if (!HeapGates::canTls(tlsPerFile, lastError, sizeof(lastError))) {
            Serial.printf("[PWNCRACK] Heap degraded before upload %u, aborting remaining\n", i);
            result.failed += (pendingCount - i);
            break;
        }

        if (uploadSingleCapture(pendingUploads[i].path, pendingUploads[i].fname22k)) {
            result.uploaded++;
            successMask |= (1 << i);
        } else {
            result.failed++;
            Serial.printf("[PWNCRACK] Failed: %s\n", pendingUploads[i].path);
        }

        // Wait for LWIP async TCP cleanup before next TLS gate check
        HeapGates::waitForLwipCleanup();
    }

    // Mark successful uploads AFTER all TLS operations complete
    if (result.uploaded > 0) {
        if (cb) cb("marking loot", 0, 0);
        loadCache();
        for (uint8_t i = 0; i < pendingCount; i++) {
            if (successMask & (1 << i)) {
                const char* fn = pendingUploads[i].filename;
                auto uit = std::lower_bound(uploadedCache.begin(), uploadedCache.end(), fn,
                    [](const UploadedEntry& e, const char* f) { return strcmp(e.filename, f) < 0; });
                if (uit == uploadedCache.end() || strcmp(uit->filename, fn) != 0) {
                    if (uploadedCache.size() < PWNCRACK_MAX_CACHE_ENTRIES) {
                        UploadedEntry entry;
                        strncpy(entry.filename, fn, sizeof(entry.filename) - 1);
                        entry.filename[sizeof(entry.filename) - 1] = '\0';
                        uploadedCache.insert(uit, entry);
                    }
                }
            }
        }
        saveUploadedList();
        Serial.printf("[PWNCRACK] Marked %u uploads after TLS complete\n", result.uploaded);
    }

    // Download potfile
    if (cb) cb("slurping potfile", 0, 0);

    freeCacheMemory();
    delay(100);

    Serial.printf("[PWNCRACK] Heap before potfile: %u largest=%u\n",
                  (unsigned int)ESP.getFreeHeap(),
                  (unsigned int)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));

    uint16_t newCracks = 0;
    bool potfileOk = false;

    HeapGates::GateStatus potGate = HeapGates::checkGate(0, HeapPolicy::kMinContigForTls);
    if (potGate.failure == HeapGates::TlsGateFailure::None) {
        potfileOk = downloadPotfile(newCracks);
        if (potfileOk) {
            result.newCracked = newCracks;
            loadCache();
            result.cracked = crackedCache.size();
        }
    } else {
        Serial.printf("[PWNCRACK] Skipping potfile: insufficient heap (%u < %u)\n",
                      (unsigned int)potGate.largestBlock,
                      (unsigned int)HeapPolicy::kMinContigForTls);
        snprintf(lastError, sizeof(lastError), "POTFILE SKIP: LOW HEAP");
    }

    // Graceful degradation: partial success if uploads worked but potfile failed
    if (!potfileOk && result.uploaded > 0) {
        snprintf(result.error, sizeof(result.error), "POTFILE: %s", lastError);
        result.success = true;
    } else if (!potfileOk) {
        strncpy(result.error, lastError, sizeof(result.error) - 1);
        result.success = (result.failed == 0);
    } else {
        result.success = (result.failed == 0);
    }

    busy = false;
    Serial.printf("[PWNCRACK] Sync complete: uploaded=%u failed=%u cracked=%u\n",
                  (unsigned int)result.uploaded, (unsigned int)result.failed,
                  (unsigned int)result.cracked);

    return result;
}
