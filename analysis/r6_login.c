/*
 * r6_login.c — Call the DLL's LoginArg serializer directly
 *
 * Uses Mode A (LoadLibraryA with DllMain) because we need the type
 * descriptors initialized in BSS. Output via Win32 file API since
 * printf hangs after DllMain.
 *
 * Plan:
 * 1. Load DLL (DllMain initializes BSS type descriptors)
 * 2. Construct a LoginArg object using its constructor
 * 3. Set field values (strings, bools, etc.)
 * 4. Call the serializer chain
 * 5. Dump the output bytes
 *
 * LoginArg constructor: FUN_100ba130 (from PLAN.md)
 * The constructor sets up vtable and field descriptors.
 */

#include <windows.h>
#include <string.h>

static HANDLE gf;
static void wlog(const char *fmt, ...) {
    char buf[2048]; va_list ap; va_start(ap, fmt);
    int n = wvsprintfA(buf, fmt, ap); va_end(ap);
    DWORD w; WriteFile(gf, buf, n, &w, NULL);
    FlushFileBuffers(gf);
}

static void hexdump(const unsigned char *data, int len) {
    int i;
    for (i = 0; i < len; i++) {
        if (i > 0 && i % 32 == 0) wlog("\r\n");
        wlog("%02x", data[i]);
    }
    wlog("\r\n");
}

static DWORD WINAPI timeout_thread(LPVOID param) {
    Sleep(30000);
    HANDLE f = CreateFileA("C:\\timeout.txt", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, 0, NULL);
    DWORD w;
    WriteFile(f, "TIMEOUT\r\n", 9, &w, NULL);
    CloseHandle(f);
    ExitProcess(42);
    return 0;
}

int main() {
    gf = CreateFileA("C:\\r6_login.txt", GENERIC_WRITE, 0, NULL,
                     CREATE_ALWAYS, 0, NULL);
    CreateThread(NULL, 0, timeout_thread, NULL, 0, NULL);

    wlog("Loading DLL...\r\n");
    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { wlog("FAIL %lu\r\n", GetLastError()); CloseHandle(gf); return 1; }
    DWORD base = (DWORD)h;
    wlog("base=0x%08x\r\n", base);

    /* === Step 1: Construct LoginArg === */
    /* FUN_100ba130 is the LoginArg constructor (from PLAN.md) */
    /* It takes a 'this' pointer to uninitialized memory */
    typedef void* (__fastcall *fn_ctor)(void *obj);
    BYTE login_obj[2048];
    memset(login_obj, 0, sizeof(login_obj));
    ((fn_ctor)(base + 0x0BA130))(login_obj);
    wlog("LoginArg constructed, vtable=0x%08x\r\n", *(DWORD*)login_obj);

    /* === Step 2: Explore the object layout === */
    /* Dump first 128 bytes to see what the constructor set up */
    wlog("LoginArg object (first 128 bytes):\r\n");
    hexdump(login_obj, 128);

    /* === Step 3: Get the type descriptor === */
    /* vtable[1] returns the type descriptor */
    DWORD *vt = *(DWORD**)login_obj;
    wlog("vtable[0]=0x%08x (dtor)\r\n", vt[0]);
    wlog("vtable[1]=0x%08x (get_desc)\r\n", vt[1]);
    wlog("vtable[2]=0x%08x\r\n", vt[2]);

    typedef DWORD* (__fastcall *fn_desc)(void*);
    DWORD *desc = ((fn_desc)vt[1])(login_obj);
    wlog("descriptor=0x%08x\r\n", (DWORD)desc);

    /* Dump descriptor */
    wlog("Descriptor (first 64 bytes):\r\n");
    hexdump((unsigned char*)desc, 64);

    /* === Step 4: Walk the field list === */
    /* From trace_ll.c: desc[7] (offset 0x1C) is the linked list head */
    /* Each node: [0]=prev, [1]=serializer, [2]=name_struct, [3]=version, [4]=sub_type, [5]=next */
    DWORD sentinel = desc[0];
    DWORD head = desc[7];
    wlog("\r\nField list (sentinel=0x%08x, head=0x%08x):\r\n", sentinel, head);

    DWORD node = head;
    int i;
    for (i = 0; i < 30 && node != 0 && node != sentinel; i++) {
        DWORD *fd = (DWORD*)node;
        /* Try to get field name */
        char name[32] = "?";
        DWORD ns = fd[2];
        if (ns > base && ns < base + 0x400000) {
            DWORD *nsp = (DWORD*)ns;
            DWORD sp = nsp[2];
            if (sp > base + 0x2AE000 && sp < base + 0x30A200) {
                char *s = (char*)sp;
                int j;
                for (j = 0; j < 28 && s[j] >= 0x20 && s[j] <= 0x7e; j++) name[j] = s[j];
                name[j] = 0;
            }
        }
        /* Get type info */
        DWORD type_desc = fd[4];
        DWORD type_id = 0;
        if (type_desc > base && type_desc < base + 0x400000) {
            type_id = *(DWORD*)(type_desc + 4);
        }
        /* Get flags at fd+0x16 (byte) */
        BYTE flags = *((BYTE*)fd + 0x16);

        wlog("[%2d] %-25s type=%d flags=%d fd=0x%08x\r\n",
             i, name, type_id, flags, node);
        node = fd[5];
    }

    /* === Step 5: Try to set a string field value === */
    /* The LoginArg object has string fields at known offsets */
    /* From the constructor, we need to find where strings are stored */
    /* Let's look at what the object looks like after construction */
    wlog("\r\nLoginArg object (bytes 0-255):\r\n");
    hexdump(login_obj, 256);

    CloseHandle(gf);
    FreeLibrary(h);
    return 0;
}
