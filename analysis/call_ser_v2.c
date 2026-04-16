#include <windows.h>
#include <stdio.h>
#include <string.h>

static HANDLE gf;
static void wlog(const char *fmt, ...) {
    char buf[1024]; va_list ap; va_start(ap, fmt);
    int n = wvsprintfA(buf, fmt, ap); va_end(ap);
    DWORD w; WriteFile(gf, buf, n, &w, NULL);
    FlushFileBuffers(gf);
}

int main() {
    gf = CreateFileA("C:\\ser.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (gf == INVALID_HANDLE_VALUE) return 1;

    wlog("1 loading\r\n");
    /* Flush before LoadLibrary since DllMain may interfere */
    FlushFileBuffers(gf);
    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { wlog("FAIL\r\n"); CloseHandle(gf); return 1; }
    DWORD base = (DWORD)h;
    wlog("2 base=0x%08x\r\n", base);

    typedef void* (__fastcall *fn_ctor)(void *obj);
    BYTE body[1024];
    memset(body, 0, sizeof(body));
    ((fn_ctor)(base + 0x0B4A30))(body);
    wlog("3 body\r\n");

    DWORD *vt = *(DWORD**)(body);
    typedef DWORD* (__fastcall *fn_desc)(void*);
    DWORD *desc = ((fn_desc)vt[1])(body);
    wlog("4 desc=0x%08x\r\n", (DWORD)desc);

    /* Version info */
    DWORD *ver_src = (DWORD*)(desc[2] + 8);
    wlog("5 ver_src=0x%08x [0]=0x%08x [1]=0x%08x\r\n",
         (DWORD)ver_src, ver_src[0], ver_src[1]);

    typedef DWORD (__fastcall *fn_ver)(DWORD*);
    wlog("6 calling ver\r\n");
    DWORD vr = ((fn_ver)(base + 0x1b3f20))(ver_src);
    wlog("7 vr=0x%08x\r\n", vr);

    DWORD vi[3] = {vr, ver_src[0], ver_src[1]};

    /* Prepare */
    DWORD *dvt = *(DWORD**)desc;
    wlog("8 calling prepare\r\n");
    typedef int (__thiscall *fn3)(void*, void*, int, DWORD*);
    int pr = ((fn3)dvt[7])(desc, body, 0, vi);
    wlog("9 prepare=%d\r\n", pr);

    /* Output buffer — large, zeroed */
    BYTE *out = (BYTE*)VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
    wlog("10 out=0x%08x\r\n", (DWORD)out);

    /* Compound serialize */
    wlog("11 calling serialize\r\n");
    typedef int (__thiscall *fn4)(void*, void*, BYTE*, DWORD*);
    int sr = ((fn4)dvt[2])(desc, body, out, vi);
    wlog("12 ser=%d\r\n", sr);

    wlog("13 out: ");
    int i;
    for (i = 0; i < 32; i++) wlog("%02x", out[i]);
    wlog("\r\n");

    VirtualFree(out, 0, MEM_RELEASE);
    CloseHandle(gf);
    FreeLibrary(h);
    return 0;
}
