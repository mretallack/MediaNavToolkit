#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    FILE *f = fopen("C:\\ser.txt", "w");
    if (!f) return 1;
    fprintf(f, "1 start\n"); fflush(f);

    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    fprintf(f, "2 base=0x%08x\n", (unsigned)h); fflush(f);
    if (!h) { fclose(f); return 1; }
    unsigned base = (unsigned)h;

    typedef void* (__fastcall *fn_ctor)(void *obj);
    unsigned char body[1024];
    memset(body, 0, sizeof(body));
    ((fn_ctor)(base + 0x0B4A30))(body);
    fprintf(f, "3 body_vt=0x%08x\n", *(unsigned*)body); fflush(f);

    unsigned *vt = *(unsigned**)(body);
    typedef unsigned* (__fastcall *fn_desc)(void*);
    unsigned *desc = ((fn_desc)vt[1])(body);
    fprintf(f, "4 desc=0x%08x\n", (unsigned)desc); fflush(f);

    unsigned *ver_src = (unsigned*)(desc[2] + 8);
    fprintf(f, "5 ver_src=0x%08x [0]=0x%08x [1]=0x%08x\n",
            (unsigned)ver_src, ver_src[0], ver_src[1]); fflush(f);

    typedef unsigned (__fastcall *fn_ver)(unsigned*);
    unsigned vr = ((fn_ver)(base + 0x1b3f20))(ver_src);
    fprintf(f, "6 vr=0x%08x\n", vr); fflush(f);

    unsigned vi[3] = {vr, ver_src[0], ver_src[1]};

    unsigned *dvt = *(unsigned**)desc;
    fprintf(f, "7 prepare=0x%08x\n", dvt[7]); fflush(f);

    typedef int (__thiscall *fn3)(void*, void*, int, unsigned*);
    int pr = ((fn3)dvt[7])(desc, body, 0, vi);
    fprintf(f, "8 prepare=%d\n", pr); fflush(f);

    unsigned char *out = (unsigned char*)VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
    fprintf(f, "9 calling serialize\n"); fflush(f);

    typedef int (__thiscall *fn4)(void*, void*, unsigned char*, unsigned*);
    int sr = ((fn4)dvt[2])(desc, body, out, vi);
    fprintf(f, "10 ser=%d\n", sr); fflush(f);

    fprintf(f, "11 out: ");
    int i;
    for (i = 0; i < 16; i++) fprintf(f, "%02x", out[i]);
    fprintf(f, "\n");

    fclose(f);
    VirtualFree(out, 0, MEM_RELEASE);
    FreeLibrary(h);
    return 0;
}
