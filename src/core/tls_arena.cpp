// TlsArena implementation

#include "tls_arena.h"

#include <Arduino.h>
#include <cstdlib>
#include <cstring>
#include <multi_heap.h>
#include <mbedtls/platform.h>

namespace {
    multi_heap_handle_t g_heap = nullptr;
    uint8_t* g_lo = nullptr;
    uint8_t* g_hi = nullptr;

    // mbedTLS allocator: serve from the static arena first, fall back to the
    // system heap when the arena is full. memset because mbedtls_calloc semantics
    // require zeroed memory.
    void* arena_calloc(size_t n, size_t size) {
        size_t need = n * size;
        if (size != 0 && need / size != n) return nullptr;  // multiply overflow
        if (g_heap) {
            void* p = multi_heap_malloc(g_heap, need);
            if (p) { memset(p, 0, need); return p; }
        }
        return calloc(n, size);
    }

    void arena_free(void* p) {
        if (!p) return;
        if ((uint8_t*)p >= g_lo && (uint8_t*)p < g_hi) {
            multi_heap_free(g_heap, p);
            return;
        }
        free(p);
    }
}

namespace TlsArena {

void begin(void* buf, size_t size) {
    if (g_heap || !buf || size < 1024) return;  // already active, or unusable

    g_heap = multi_heap_register(buf, size);
    if (!g_heap) {
        Serial.println("[TLS_ARENA] register failed; mbedTLS uses heap only");
        return;
    }
    g_lo = (uint8_t*)buf;
    g_hi = g_lo + size;
    mbedtls_platform_set_calloc_free(arena_calloc, arena_free);
    Serial.printf("[TLS_ARENA] begin: arena=%uB usable=%uB\n",
                  (unsigned)size, (unsigned)multi_heap_free_size(g_heap));
}

void end() {
    if (!g_heap) return;
    // Restore the stock allocator. With CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC off, the
    // ESP-IDF default mbedtls_calloc/free route to libc calloc/free (the heap),
    // so restoring those is equivalent to the original behaviour.
    mbedtls_platform_set_calloc_free(calloc, free);
    g_heap = nullptr;
    g_lo = g_hi = nullptr;
    Serial.println("[TLS_ARENA] end");
}

}  // namespace TlsArena
