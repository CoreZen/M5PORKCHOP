// pwncrack.org hash-cracking sync client
// Uploads .22000 / .hc22000 captures for distributed cracking
#pragma once

#include <Arduino.h>
#include <vector>
#include "../core/heap_policy.h"

// Sync operation result
struct PwncrackSyncResult {
    bool success;
    uint8_t uploaded;
    uint8_t failed;
    uint8_t skipped;      // Already uploaded
    uint16_t cracked;     // Total cracked after potfile download
    uint16_t newCracked;  // New cracks found this sync
    char error[48];
};

// Sync progress callback for UI updates
typedef void (*PwncrackProgressCallback)(const char* status, uint8_t progress, uint8_t total);

class Pwncrack {
public:
    // Sync status
    static bool isBusy();

    // Local cache queries (no WiFi needed)
    static bool loadCache();                          // Load cache from SD
    static bool isCracked(const char* bssid);         // Check if BSSID is cracked
    static const char* getPassword(const char* bssid); // Get password for BSSID (returns "" if not found)
    static uint16_t getCrackedCount();                // Total cracked in cache
    static void normalizeBSSID_Char(const char* bssid, char* output, size_t outLen);

    // Upload tracking
    static bool isUploaded(const char* filename);    // Check if file already uploaded
    static void markAsUploaded(const char* filename); // Mark filename as uploaded

    // Batch upload mode (reduces SD writes from N to 1)
    static void beginBatchUpload();
    static void endBatchUpload();

    // Network operations (require WiFi + sufficient heap)
    static bool hasApiKey();   // Check if pwncrack key configured
    static bool canSync();     // Check heap requirements (~35KB)
    static PwncrackSyncResult syncCaptures(PwncrackProgressCallback cb = nullptr); // Full sync

    // Status
    static const char* getLastError();

    // Free cached results from memory
    static void freeCacheMemory();

    static bool isCacheLoaded() { return cacheLoaded; }

private:
    static bool cacheLoaded;
    static char lastError[64];
    static volatile bool busy;
    static bool batchMode;

    // Flat cache entries — no std::map, no String
    struct CrackedEntry {
        char bssid[13];    // Normalized BSSID (no colons, uppercase)
        char password[64];
    };
    struct UploadedEntry {
        char filename[48]; // Track by filename (not BSSID — pwncrack tracks files)
    };
    static std::vector<CrackedEntry> crackedCache;
    static std::vector<UploadedEntry> uploadedCache;

    static const CrackedEntry* findCracked(const char* normalizedBssid);
    static bool findUploaded(const char* filename);

    // Helpers
    static bool loadUploadedList();
    static bool saveUploadedList();

    // Network helpers (internal)
    static bool uploadSingleCapture(const char* filepath, const char* filename22000);
    static bool downloadPotfile(uint16_t& newCracks);
};
