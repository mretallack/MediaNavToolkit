#include <windows.h>
#include <stdio.h>
#include <string.h>

/* Hook the bit writer functions by patching them to log calls */
/* FUN_101a9e80 = write_1bit_lsb (RVA 0x1a9e80) */
/* FUN_101a8150 = write_nbits_msb (RVA 0x1a8150) */
/* FUN_101a8310 = write_nbits_lsb (RVA 0x1a8310) */

/* Instead of hooking, let's call the serializer entry point directly */
/* FUN_101a9930 (RVA 0x1a9930) = serialize entry */
/* It takes: this=body_object, param2=output_buffer, param3=version_info */

/* But we don't know how to construct the body object. */
/* Instead, let's hook the bit writers and call NngineStart to trigger */
/* a real serialization, then capture the bit writes. */

/* Simplest approach: patch the bit writer to log to a file */

static FILE *logfile = NULL;
static DWORD dll_base = 0;

/* Original function bytes (for unhooking) */
static BYTE orig_1bit[16];
static BYTE orig_nmsb[16];

/* Trampoline for write_1bit_lsb */
typedef void (__thiscall *fn_write_1bit)(void *this_ptr, int value);
typedef void (__thiscall *fn_write_nmsb)(void *this_ptr, DWORD value, int nbits);

static fn_write_1bit real_write_1bit;
static fn_write_nmsb real_write_nmsb;

/* We can't easily hook __thiscall in C. Let's use a different approach: */
/* Set a hardware breakpoint on the bit writer and use SEH to catch it. */

/* Actually, the simplest approach: just dump the output buffer AFTER */
/* a known serialization call. We know the boot request produces "50 86". */
/* Let's find where the output buffer is and read it. */

/* EVEN SIMPLER: Call the exported NngineStart and capture network traffic. */
/* But that requires a full environment. */

/* SIMPLEST OF ALL: Read the bit writer function code to understand */
/* the type_id dispatch. The serialize function at RVA 0x1a67f0 */
/* dispatches based on type_id. Let's read its code. */

int main() {
    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { printf("FAIL: %lu\n", GetLastError()); return 1; }
    DWORD base = (DWORD)h;
    printf("BASE: 0x%08x\n", base);

    /* Dump the serialize function at RVA 0x1a67f0 */
    BYTE *func = (BYTE*)(base + 0x1a67f0);
    printf("\nSerialize function (RVA 0x1a67f0) first 128 bytes:\n");
    for (int i = 0; i < 128; i += 16) {
        printf("  %04x: ", i);
        for (int j = 0; j < 16; j++) printf("%02x ", func[i+j]);
        printf("\n");
    }

    /* Also dump the field value serializer at RVA 0x1a1f80 */
    func = (BYTE*)(base + 0x1a1f80);
    printf("\nField value serializer (RVA 0x1a1f80) first 64 bytes:\n");
    for (int i = 0; i < 64; i += 16) {
        printf("  %04x: ", i);
        for (int j = 0; j < 16; j++) printf("%02x ", func[i+j]);
        printf("\n");
    }

    /* Dump the compound serializer at RVA 0x1a8e80 */
    func = (BYTE*)(base + 0x1a8e80);
    printf("\nCompound serializer (RVA 0x1a8e80) first 64 bytes:\n");
    for (int i = 0; i < 64; i += 16) {
        printf("  %04x: ", i);
        for (int j = 0; j < 16; j++) printf("%02x ", func[i+j]);
        printf("\n");
    }

    /* Now the key question: what does the serialize function do with type_id? */
    /* Let me read the vtable functions for the type objects */
    /* vtable at 0x7ecc236c has: */
    /* [0] RVA 0x1a6900 - destructor? */
    /* [1] RVA 0x1a6890 - get_descriptor? */
    /* [2] RVA 0x1a67f0 - serialize (write) */
    /* [3] RVA 0x1a67d0 - ? */
    /* [4] RVA 0x1a67a0 - ? */
    /* [5] RVA 0x1a2be0 - ? */
    /* [6] RVA 0x1a2bf0 - ? */
    /* [7] RVA 0x1a2c00 - ? */
    /* [8] RVA 0x00e830 - ? */
    /* [9] RVA 0x1a6a40 - ? */
    /* [10] RVA 0x1a6940 - ? */
    /* [11] RVA 0x1a9a30 - ? */

    /* vtable[5] at RVA 0x1a2be0 - this might be the "get_value" function */
    /* vtable[8] at RVA 0x00e830 - this is in early .text, might be trivial */

    /* Let me check vtable[8] - from FUN_101a1f80, it calls vtable[0x20] = vtable[8] */
    func = (BYTE*)(base + 0x00e830);
    printf("\nvtable[8] (RVA 0x00e830) first 16 bytes:\n  ");
    for (int j = 0; j < 16; j++) printf("%02x ", func[j]);
    printf("\n");
    /* If it's "ret 4" (0xC2 0x04 0x00), it's a no-op */

    /* vtable[5] at RVA 0x1a2be0 */
    func = (BYTE*)(base + 0x1a2be0);
    printf("\nvtable[5] (RVA 0x1a2be0) first 32 bytes:\n  ");
    for (int j = 0; j < 32; j++) printf("%02x ", func[j]);
    printf("\n");

    FreeLibrary(h);
    return 0;
}
