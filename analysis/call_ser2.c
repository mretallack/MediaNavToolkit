#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { printf("FAIL: %lu\n", GetLastError()); return 1; }
    DWORD base = (DWORD)h;
    printf("BASE: 0x%08x\n", base);

    /* Construct body object */
    typedef void* (__fastcall *fn_ctor)(void *obj);
    fn_ctor body_ctor = (fn_ctor)(base + 0x0B4A30);
    BYTE body_obj[512];
    memset(body_obj, 0, sizeof(body_obj));
    body_ctor(body_obj);

    /* Create output buffer - needs to be large enough */
    /* The BitStream structure from the assembly: */
    /* [0] buf_ptr, [4] bit_pos, [8] byte_pos, ... [0x12] error_flag, [0x14] capacity */
    BYTE output_data[4096];
    memset(output_data, 0xCC, sizeof(output_data));

    /* Output structure (at least 0x18 bytes) */
    BYTE output_struct[64];
    memset(output_struct, 0, sizeof(output_struct));
    *(DWORD*)(output_struct + 0) = (DWORD)output_data;  /* buffer */
    *(DWORD*)(output_struct + 4) = 0;                     /* bit_pos */
    *(DWORD*)(output_struct + 8) = 0;                     /* byte_pos (or ptr) */
    *(DWORD*)(output_struct + 0x14) = 4096;              /* capacity */

    /* Actually, looking at the code more carefully: */
    /* FUN_101a8150 reads: param_1[0]=buf, param_1[1]=bit_pos, param_1[2]=byte_pos */
    /* And FUN_101a8820 is called to ensure capacity */
    /* The output struct might be more complex */

    /* Let me try a different approach: allocate the output struct */
    /* using the DLL's own allocator */

    /* FUN_101a9930 signature: */
    /* __thiscall(this=body_obj, param2=output_struct, param3=version_or_null) */
    /* Returns 1 on success, 0 on failure */

    /* Use inline asm to call with correct __thiscall convention */
    DWORD serialize_addr = base + 0x1a9930;
    DWORD body_ptr = (DWORD)body_obj;
    DWORD out_ptr = (DWORD)output_struct;
    int result;

    __asm__ volatile (
        "push $0\n\t"           /* param3 = NULL (use default version) */
        "push %[out]\n\t"       /* param2 = output_struct */
        "mov %[body], %%ecx\n\t" /* this = body_obj */
        "call *%[func]\n\t"
        "mov %%eax, %[res]\n\t"
        : [res] "=r" (result)
        : [body] "r" (body_ptr), [out] "r" (out_ptr), [func] "r" (serialize_addr)
        : "ecx", "edx", "memory"
    );

    printf("Serialize returned: %d\n", result);
    printf("Output struct: ");
    for (int i = 0; i < 32; i++) printf("%02x", output_struct[i]);
    printf("\n");

    DWORD byte_pos = *(DWORD*)(output_struct + 8);
    DWORD bit_pos = *(DWORD*)(output_struct + 4);
    printf("byte_pos=%u bit_pos=%u\n", byte_pos, bit_pos);

    int total = byte_pos + (bit_pos > 0 ? 1 : 0);
    if (total > 0 && total < 100) {
        printf("Output data (%d bytes): ", total);
        for (int i = 0; i < total; i++) printf("%02x", output_data[i]);
        printf("\n");
    }

    /* Check if output_data was written to */
    int written = 0;
    for (int i = 0; i < 100; i++) {
        if (output_data[i] != 0xCC) written++;
    }
    printf("Modified bytes in first 100: %d\n", written);

    FreeLibrary(h);
    return 0;
}
