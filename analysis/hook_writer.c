#include <windows.h>
#include <stdio.h>
#include <string.h>

/* Load nngine.dll with DllMain (Mode A) to get initialized BSS.
   Use Win32 file I/O since printf hangs after LoadLibraryA.
   
   Then construct a body object, set Country=0, and call the serializer.
   Hook the byte buffer writer to capture what gets written.
*/

static HANDLE gf;
static void wlog(const char *fmt, ...) {
    char buf[1024]; va_list ap; va_start(ap, fmt);
    int n = wvsprintfA(buf, fmt, ap); va_end(ap);
    DWORD w; WriteFile(gf, buf, n, &w, NULL);
}

int main() {
    /* Open log file BEFORE loading DLL */
    gf = CreateFileA("C:\\hook.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (gf == INVALID_HANDLE_VALUE) return 1;
    wlog("start\r\n");

    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { wlog("FAIL %lu\r\n", GetLastError()); CloseHandle(gf); return 1; }
    DWORD base = (DWORD)h;
    wlog("base=0x%08x\r\n", base);

    /* Construct body object */
    typedef void* (__fastcall *fn_ctor)(void *obj);
    fn_ctor body_ctor = (fn_ctor)(base + 0x0B4A30);
    BYTE body[1024];
    memset(body, 0, sizeof(body));
    body_ctor(body);
    wlog("body vt=0x%08x\r\n", *(DWORD*)body);

    /* Get descriptor */
    DWORD *vt = *(DWORD**)(body);
    typedef DWORD* (__fastcall *fn_desc)(void*);
    DWORD *desc = ((fn_desc)vt[1])(body);
    wlog("desc=0x%08x\r\n", (DWORD)desc);

    /* The descriptor is the triplet array at RVA 0x30DE14 */
    /* Each triplet: [handler_vt:4][fd:4][sub:4] */
    /* The handler_vt[2] is the compound serializer */

    /* Let me check: what does the compound serializer's vtable[7] do? */
    /* vtable[7] = RVA 0x1a8bf0 (from earlier dump) */
    /* This is the "prepare" function that hangs. */
    /* Let me skip it and call vtable[2] directly. */

    DWORD handler_vt = desc[0]; /* first triplet's handler */
    DWORD *hvt = (DWORD*)handler_vt;
    wlog("handler_vt=0x%08x\r\n", handler_vt);
    wlog("hvt[2]=0x%08x (compound ser)\r\n", hvt[2]);
    wlog("hvt[7]=0x%08x (prepare)\r\n", hvt[7]);

    /* The compound serializer (hvt[2]) takes: */
    /* __thiscall: ecx = descriptor */
    /* stack: body_obj, bitstream, version_info */

    /* But we don't know the correct bitstream structure. */
    /* And the compound serializer iterates the linked list which */
    /* might not be properly initialized without the prepare step. */

    /* Let me try calling the prepare function with a timeout */
    /* Actually, the prepare function (vtable[7]) might just be */
    /* setting up the linked list. Let me check what it does. */

    /* RVA 0x1a8bf0 */
    BYTE *prep_code = (BYTE*)(base + 0x1a8bf0);
    wlog("\r\nprepare func bytes: ");
    int i;
    for (i = 0; i < 16; i++) wlog("%02x ", prep_code[i]);
    wlog("\r\n");

    /* Also check vtable[4] = RVA 0x1a8b00 */
    BYTE *vt4_code = (BYTE*)(base + 0x1a8b00);
    wlog("vtable[4] bytes: ");
    for (i = 0; i < 16; i++) wlog("%02x ", vt4_code[i]);
    wlog("\r\n");

    /* Let me try: instead of calling the serializer, */
    /* just dump the body object's field values. */
    /* The body object has fields at known offsets. */
    /* After construction, all fields should be default (empty/zero). */

    wlog("\r\nBody object dump (first 128 bytes):\r\n");
    for (i = 0; i < 128; i += 16) {
        wlog("  +0x%02x: ", i);
        int j;
        for (j = 0; j < 16; j++) wlog("%02x ", body[i+j]);
        wlog("\r\n");
    }

    FreeLibrary(h);
    CloseHandle(gf);
    return 0;
}
