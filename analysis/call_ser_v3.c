#include <windows.h>
#include <string.h>

static void wlog(const char *msg) {
    HANDLE f = CreateFileA("C:\\ser.txt", FILE_APPEND_DATA, FILE_SHARE_READ,
                           NULL, OPEN_ALWAYS, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(f, msg, lstrlenA(msg), &w, NULL);
        CloseHandle(f);
    }
}

static void wlogx(const char *prefix, DWORD val) {
    char buf[80];
    wsprintfA(buf, "%s 0x%08x\r\n", prefix, val);
    wlog(buf);
}

int main() {
    /* Delete old log */
    DeleteFileA("C:\\ser.txt");
    wlog("1 start\r\n");

    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    wlogx("2 base", (DWORD)h);
    if (!h) return 1;
    DWORD base = (DWORD)h;

    typedef void* (__fastcall *fn_ctor)(void *obj);
    BYTE body[1024];
    memset(body, 0, sizeof(body));
    ((fn_ctor)(base + 0x0B4A30))(body);
    wlogx("3 body_vt", *(DWORD*)body);

    DWORD *vt = *(DWORD**)(body);
    typedef DWORD* (__fastcall *fn_desc)(void*);
    DWORD *desc = ((fn_desc)vt[1])(body);
    wlogx("4 desc", (DWORD)desc);

    DWORD *ver_src = (DWORD*)(desc[2] + 8);
    wlogx("5 ver_src", (DWORD)ver_src);

    typedef DWORD (__fastcall *fn_ver)(DWORD*);
    DWORD vr = ((fn_ver)(base + 0x1b3f20))(ver_src);
    wlogx("6 vr", vr);

    DWORD vi[3] = {vr, ver_src[0], ver_src[1]};

    DWORD *dvt = *(DWORD**)desc;
    wlogx("7 dvt7", dvt[7]);
    wlog("8 calling prepare\r\n");

    typedef int (__thiscall *fn3)(void*, void*, int, DWORD*);
    int pr = ((fn3)dvt[7])(desc, body, 0, vi);
    wlogx("9 prepare", pr);

    BYTE *out = (BYTE*)VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
    wlog("10 calling serialize\r\n");

    typedef int (__thiscall *fn4)(void*, void*, BYTE*, DWORD*);
    int sr = ((fn4)dvt[2])(desc, body, out, vi);
    wlogx("11 ser", sr);

    /* Dump output */
    char hex[128] = "12 out: ";
    int i;
    for (i = 0; i < 16; i++) wsprintfA(hex + lstrlenA(hex), "%02x", out[i]);
    lstrcatA(hex, "\r\n");
    wlog(hex);

    VirtualFree(out, 0, MEM_RELEASE);
    FreeLibrary(h);
    return 0;
}
