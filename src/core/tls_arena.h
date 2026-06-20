// TlsArena - lend a fixed static buffer to mbedTLS as its allocation arena
// during TLS sync, so the ~16KB TLS record buffer comes from reserved static
// memory instead of the heap (avoids heap exhaustion + fragmentation)
#pragma once

#include <cstddef>

namespace TlsArena {
    // Install `buf` (size bytes) as mbedTLS's primary allocator for the duration
    // of a TLS operation. Allocations are served from the arena first; when it is
    // exhausted they fall back to the system heap (transient — freed on connection
    // close, so they coalesce and don't permanently fragment).
    //
    // MUST be paired with end(). Not reentrant. Call from a single task with no
    // other concurrent mbedTLS user (NetworkRecon is paused during sync). The
    // buffer must NOT be read/written by anything else between begin() and end().
    void begin(void* buf, size_t size);

    // Restore the default mbedTLS allocator. Safe to call if begin() was a no-op.
    void end();
}
