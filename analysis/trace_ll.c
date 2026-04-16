#include <windows.h>
#include <stdio.h>
#include <string.h>

static HANDLE gf;
static void wlog(const char *fmt, ...) {
    char buf[1024]; va_list ap; va_start(ap, fmt);
    int n = wvsprintfA(buf, fmt, ap); va_end(ap);
    DWORD w; WriteFile(gf, buf, n, &w, NULL);
}

int main() {
    gf = CreateFileA("C:\\ll.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { wlog("FAIL\r\n"); CloseHandle(gf); return 1; }
    DWORD base = (DWORD)h;
    wlog("base=0x%08x\r\n", base);

    /* Construct body */
    typedef void* (__fastcall *fn_ctor)(void *obj);
    BYTE body[1024];
    memset(body, 0, sizeof(body));
    ((fn_ctor)(base + 0x0B4A30))(body);

    /* Get descriptor via vtable[1] */
    DWORD *vt = *(DWORD**)(body);
    typedef DWORD* (__fastcall *fn_desc)(void*);
    DWORD *desc = ((fn_desc)vt[1])(body);
    wlog("desc=0x%08x\r\n", (DWORD)desc);

    /* The iterator FUN_101a9da0 reads:
       edi = desc (the compound type descriptor)
       [edi+0x00] = sentinel (first DWORD)
       [edi+0x1C] = head of linked list
       Each node: [0]=prev, [4]=getter, [8]=name, [12]=ver, [16]=type, [20]=next
       The list terminates when next == sentinel or next == 0
    */

    DWORD sentinel = desc[0];
    wlog("sentinel=0x%08x\r\n", sentinel);

    /* desc is the triplet array. desc[0] is the first triplet's handler_vt.
       But the iterator reads desc[7] (offset 0x1C) as the list head.
       desc[7] is the SECOND triplet's fd_ptr. */
    DWORD head = desc[7]; /* offset 0x1C */
    wlog("head=0x%08x (desc[7])\r\n", head);

    /* Follow the linked list via fd[5] (offset 20 = next ptr) */
    DWORD node = head;
    int i;
    for (i = 0; i < 100 && node != 0 && node != sentinel; i++) {
        DWORD *fd = (DWORD*)node;
        DWORD next = fd[5];

        /* Try to get name */
        char name[25] = "?";
        DWORD ns = fd[2];
        if (ns > base && ns < base + 0x400000) {
            /* Try name_struct[2] */
            DWORD *nsp = (DWORD*)ns;
            if ((DWORD)nsp > base && (DWORD)nsp < base + 0x400000) {
                DWORD sp = nsp[2];
                if (sp > base + 0x2AE000 && sp < base + 0x30A200) {
                    char *s = (char*)sp;
                    int j;
                    for (j = 0; j < 20 && s[j] >= 0x20 && s[j] <= 0x7e; j++) name[j] = s[j];
                    name[j] = 0;
                }
            }
        }

        wlog("[%2d] 0x%08x %-20s fd[0]=0x%08x fd[5]=0x%08x\r\n",
             i, node, name, fd[0], next);
        node = next;
    }
    wlog("stopped: i=%d node=0x%08x sentinel=0x%08x\r\n", i, node, sentinel);

    if (node == sentinel) wlog("LIST TERMINATED PROPERLY\r\n");
    else if (node == 0) wlog("LIST ENDED WITH NULL\r\n");
    else wlog("LIST DID NOT TERMINATE (possible cycle)\r\n");

    FreeLibrary(h);
    CloseHandle(gf);
    return 0;
}
