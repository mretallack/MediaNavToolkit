#include <windows.h>
#include <stdio.h>
#include <string.h>

static HANDLE gf;
static void wlog(const char *fmt, ...) {
    char buf[1024]; va_list ap; va_start(ap, fmt);
    int n = wvsprintfA(buf, fmt, ap); va_end(ap);
    DWORD w; WriteFile(gf, buf, n, &w, NULL);
}

static DWORD WINAPI timeout_thread(LPVOID param) {
    Sleep(5000);
    /* Dump what we have so far */
    HANDLE f = CreateFileA("C:\\timeout.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    char buf[64] = "TIMEOUT after 5s\r\n";
    DWORD w;
    WriteFile(f, buf, 18, &w, NULL);
    CloseHandle(f);
    ExitProcess(42);
    return 0;
}

int main() {
    gf = CreateFileA("C:\\ser.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    CreateThread(NULL, 0, timeout_thread, NULL, 0, NULL);

    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { wlog("FAIL\r\n"); CloseHandle(gf); return 1; }
    DWORD base = (DWORD)h;
    wlog("base=0x%08x\r\n", base);

    /* Construct body */
    typedef void* (__fastcall *fn_ctor)(void *obj);
    BYTE body[1024];
    memset(body, 0, sizeof(body));
    ((fn_ctor)(base + 0x0B4A30))(body);
    wlog("body ok\r\n");

    /* Get descriptor */
    DWORD *vt = *(DWORD**)(body);
    typedef DWORD* (__fastcall *fn_desc)(void*);
    DWORD *desc = ((fn_desc)vt[1])(body);
    wlog("desc=0x%08x\r\n", (DWORD)desc);

    /* Setup version info like FUN_101a9930 does */
    /* param_3 = piVar2[2] + 8 = desc[2] + 8 */
    DWORD *ver_src = (DWORD*)(desc[2] + 8);
    wlog("ver_src=0x%08x\r\n", (DWORD)ver_src);

    /* FUN_101b3f20(param_3) — version processing */
    typedef DWORD (__fastcall *fn_ver)(DWORD*);
    DWORD ver_result = ((fn_ver)(base + 0x1b3f20))(ver_src);
    wlog("ver_result=0x%08x\r\n", ver_result);

    /* Build version info struct */
    DWORD ver_info[3];
    ver_info[0] = ver_result;
    ver_info[1] = ver_src[0];
    ver_info[2] = ver_src[1];
    wlog("ver_info: %08x %08x %08x\r\n", ver_info[0], ver_info[1], ver_info[2]);

    /* Call prepare: vtable[7](body, 0, &ver_info) */
    DWORD *desc_vt = *(DWORD**)desc;
    wlog("calling prepare (vtable[7]=0x%08x)\r\n", desc_vt[7]);
    FlushFileBuffers(gf);

    typedef int (__thiscall *fn_prep)(void *desc, void *body, int zero, DWORD *ver);
    int prep_result = ((fn_prep)desc_vt[7])(desc, body, 0, ver_info);
    wlog("prepare returned %d\r\n", prep_result);
    FlushFileBuffers(gf);

    /* Create output buffer */
    /* The output param_2 in FUN_101a9930 is passed directly to the compound serializer */
    /* It needs: [0x12] = 0 (error flag) */
    /* The compound serializer reads it as a bitstream */
    BYTE output[256];
    memset(output, 0, sizeof(output));

    /* Call compound serializer: vtable[2](body, output, &ver_info) */
    wlog("calling compound ser (vtable[2]=0x%08x)\r\n", desc_vt[2]);
    FlushFileBuffers(gf);

    typedef int (__thiscall *fn_ser)(void *desc, void *body, BYTE *out, DWORD *ver);
    int ser_result = ((fn_ser)desc_vt[2])(desc, body, output, ver_info);
    wlog("serialize returned %d\r\n", ser_result);

    /* Dump output */
    wlog("output: ");
    int i;
    for (i = 0; i < 32; i++) wlog("%02x", output[i]);
    wlog("\r\n");

    CloseHandle(gf);
    FreeLibrary(h);
    return 0;
}
