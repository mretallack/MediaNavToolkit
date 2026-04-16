#include <windows.h>
#include <stdio.h>

static HANDLE gf;
static void wlog(const char *fmt, ...) {
    char buf[512]; va_list ap; va_start(ap, fmt);
    int n = wvsprintfA(buf, fmt, ap); va_end(ap);
    DWORD w; WriteFile(gf, buf, n, &w, NULL);
}

int main() {
    gf = CreateFileA("C:\\flags.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { wlog("FAIL\r\n"); CloseHandle(gf); return 1; }
    DWORD base = (DWORD)h;

    DWORD *trip = (DWORD*)(base + 0x30DE08);

    wlog("Idx  Name                  Flag@0x16  fd[0]      fd[1]      fd[2]      fd[3]      fd[4]      fd[5]\r\n");

    int i;
    for (i = 0; i < 67; i++) {
        DWORD handler = trip[i*3];
        DWORD fd_ptr = trip[i*3+1];
        if (handler == 0 && fd_ptr == 0) break;

        BYTE *fd = (BYTE*)fd_ptr;
        BYTE flag = fd[0x16]; /* flag at offset 0x16 in the 24-byte field entry */

        /* Get name from fd[2] (offset 8) */
        DWORD *fdw = (DWORD*)fd_ptr;
        char namebuf[30] = "???";
        DWORD ns = fdw[2];
        if (ns > base && ns < base + 0x400000) {
            DWORD *nsp = (DWORD*)ns;
            DWORD sp = nsp[2];
            if (sp > base + 0x2AE000 && sp < base + 0x30A200) {
                char *s = (char*)sp;
                int j;
                for (j = 0; j < 25 && s[j] >= 0x20 && s[j] <= 0x7e; j++) namebuf[j] = s[j];
                namebuf[j] = 0;
            } else {
                char *s = (char*)ns;
                if (s[0] >= 'A' && s[0] <= 'z') {
                    int j;
                    for (j = 0; j < 25 && s[j] >= 0x20 && s[j] <= 0x7e; j++) namebuf[j] = s[j];
                    namebuf[j] = 0;
                }
            }
        }

        wlog("[%2d] %-22s  flag=%3d  %08x %08x %08x %08x %08x %08x\r\n",
             i, namebuf, flag, fdw[0], fdw[1], fdw[2], fdw[3], fdw[4], fdw[5]);
    }

    /* Also dump the raw bytes at offset 0x14-0x17 for each entry */
    wlog("\r\nRaw bytes at fd+0x14 to fd+0x17:\r\n");
    for (i = 0; i < 67; i++) {
        DWORD fd_ptr = trip[i*3+1];
        if (trip[i*3] == 0 && fd_ptr == 0) break;
        BYTE *fd = (BYTE*)fd_ptr;
        wlog("[%2d] %02x %02x %02x %02x\r\n", i, fd[0x14], fd[0x15], fd[0x16], fd[0x17]);
    }

    FreeLibrary(h);
    CloseHandle(gf);
    return 0;
}
