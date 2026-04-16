#include <windows.h>
#include <stdio.h>
#include <string.h>

/* Hook write_1bit_lsb to trace all bit writes */
static int trace_count = 0;
static FILE *trace_file = NULL;

/* The bit writer functions use __thiscall convention */
/* We'll use inline assembly to hook them */

/* Original function pointers */
static BYTE *orig_1bit_addr;
static BYTE *orig_nmsb_addr;
static BYTE *orig_nlsb_addr;
static BYTE orig_1bit_bytes[8];
static BYTE orig_nmsb_bytes[8];

/* Detour functions */
static void __stdcall trace_1bit(void *this_ptr, int value) {
    if (trace_file) fprintf(trace_file, "1BIT: val=%d\n", value & 1);
    trace_count++;
}

int main() {
    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { printf("FAIL: %lu\n", GetLastError()); return 1; }
    DWORD base = (DWORD)h;
    printf("BASE: 0x%08x\n", base);

    /* Instead of hooking, let's call the serializer directly */
    /* FUN_101a9930 (RVA 0x1a9930) is the serialize entry point */
    /* It's __thiscall: this=body_object, param2=output_buffer_struct, param3=version_info */

    /* First, construct the body object */
    typedef void* (__fastcall *fn_ctor)(void *obj);
    fn_ctor body_ctor = (fn_ctor)(base + 0x0B4A30);

    BYTE body_obj[512];
    memset(body_obj, 0, sizeof(body_obj));
    body_ctor(body_obj);
    printf("Body object constructed\n");

    /* The body object needs to have Country=0 set */
    /* But we don't know which offset Country is at in the object */
    /* Let's just serialize the EMPTY body object first */
    /* An empty body should produce a bitstream of all-zero presence bits */

    /* Create the output buffer structure */
    /* The output buffer is a BitStream: [buf_ptr:4][bit_pos:4][byte_pos:4][...] */
    /* From FUN_101a8150: param_1[0]=buf, param_1[1]=bit_pos, param_1[2]=byte_pos */
    BYTE output_buf[1024];
    memset(output_buf, 0, sizeof(output_buf));

    /* BitStream structure */
    DWORD bitstream[16];
    memset(bitstream, 0, sizeof(bitstream));
    bitstream[0] = (DWORD)output_buf;  /* buffer pointer */
    bitstream[1] = 0;                   /* bit position */
    bitstream[2] = 0;                   /* byte position */
    /* Need to figure out the buffer size field */
    bitstream[5] = 1024;               /* buffer capacity? */

    /* Get the serialize function */
    /* The body object's outer vtable[1] returns the descriptor */
    /* Then we call descriptor->vtable[2] (serialize) */
    DWORD outer_vt = *(DWORD*)(body_obj);
    DWORD *vt = (DWORD*)outer_vt;
    
    /* vtable[1] = get_descriptor */
    typedef DWORD* (__fastcall *fn_get_desc)(void *obj);
    fn_get_desc get_desc = (fn_get_desc)vt[1];
    
    printf("Calling get_descriptor...\n");
    DWORD *desc = get_desc(body_obj);
    printf("Descriptor: 0x%08x\n", (DWORD)desc);

    if (!desc) { printf("No descriptor!\n"); FreeLibrary(h); return 1; }

    /* The serialize entry is FUN_101a9930 */
    /* void __thiscall FUN_101a9930(body_obj, output_struct, version_info) */
    typedef int (__thiscall *fn_serialize)(void *this_ptr, void *output, void *version);
    fn_serialize serialize = (fn_serialize)(base + 0x1a9930);

    /* Version info from the sub-descriptor */
    /* sub_desc at 0x7ecbea28 has: [0x102d14b0, 1, 4, 0, ...] */
    /* version = {1, 4} = version 1.4 */
    DWORD version_info[4] = {0, 1, 4, 0};

    printf("Calling serialize...\n");
    int result = serialize(body_obj, bitstream, version_info);
    printf("Serialize returned: %d\n", result);
    printf("Bytes written: %d, bits: %d\n", bitstream[2], bitstream[1]);

    /* Dump the output */
    int total_bytes = bitstream[2] + (bitstream[1] > 0 ? 1 : 0);
    printf("Output (%d bytes): ", total_bytes);
    for (int i = 0; i < total_bytes && i < 32; i++) {
        printf("%02x", output_buf[i]);
    }
    printf("\n");

    FreeLibrary(h);
    return 0;
}
