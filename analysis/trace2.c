#include <windows.h>
#include <stdio.h>

static FILE *logf = NULL;
static DWORD addr_1bit, addr_nmsb;
static BYTE orig_1bit, orig_nmsb;
static int trace_count = 0;

static LONG WINAPI veh(EXCEPTION_POINTERS *ep) {
    DWORD eip = ep->ContextRecord->Eip;
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    if (code == EXCEPTION_SINGLE_STEP) {
        DWORD old;
        VirtualProtect((void*)addr_1bit, 1, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE*)addr_1bit = 0xCC;
        VirtualProtect((void*)addr_nmsb, 1, PAGE_EXECUTE_READWRITE, &old);
        *(BYTE*)addr_nmsb = 0xCC;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

    if (eip == addr_1bit) {
        DWORD *stk = (DWORD*)ep->ContextRecord->Esp;
        if (logf) { fprintf(logf, "P %d\n", stk[1] & 1); fflush(logf); }
        *(BYTE*)addr_1bit = orig_1bit;
        ep->ContextRecord->EFlags |= 0x100;
        trace_count++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (eip == addr_nmsb) {
        DWORD *stk = (DWORD*)ep->ContextRecord->Esp;
        if (logf) { fprintf(logf, "V %u %u\n", (BYTE)stk[2], stk[1]); fflush(logf); }
        *(BYTE*)addr_nmsb = orig_nmsb;
        ep->ContextRecord->EFlags |= 0x100;
        trace_count++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
    logf = fopen("C:\\trace.log", "w");
    if (!logf) return 1;
    fprintf(logf, "Starting\n"); fflush(logf);

    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { fprintf(logf, "FAIL\n"); fclose(logf); return 1; }
    DWORD base = (DWORD)h;
    fprintf(logf, "BASE 0x%08x\n", base); fflush(logf);

    addr_1bit = base + 0x1a9e80;
    addr_nmsb = base + 0x1a8150;

    AddVectoredExceptionHandler(1, veh);

    DWORD old;
    orig_1bit = *(BYTE*)addr_1bit;
    VirtualProtect((void*)addr_1bit, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)addr_1bit = 0xCC;

    orig_nmsb = *(BYTE*)addr_nmsb;
    VirtualProtect((void*)addr_nmsb, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)addr_nmsb = 0xCC;

    fprintf(logf, "Hooks set\n"); fflush(logf);

    /* Don't call NngineStart - it needs a full environment */
    /* Instead, call the serializer directly on an empty body object */
    typedef void* (__fastcall *fn_ctor)(void *obj);
    fn_ctor body_ctor = (fn_ctor)(base + 0x0B4A30);
    BYTE body[512];
    memset(body, 0, sizeof(body));
    body_ctor(body);
    fprintf(logf, "Body constructed\n"); fflush(logf);

    /* The serialize function FUN_101a9930 needs a proper BitStream */
    /* Let me find the BitStream constructor by looking at the callers */
    /* From FUN_100b3a60: it creates a local BitStream on the stack */
    /* The BitStream is initialized by FUN_100935c0 */

    /* Actually, let me just call the compound serializer directly */
    /* FUN_101a8e80 at RVA 0x1a8e80 */
    /* __fastcall: ecx = descriptor (from body vtable[1]) */
    /* stack: param2 = body_obj, param3 = bitstream, param4 = version */

    /* Get descriptor */
    DWORD *vt = *(DWORD**)(body);
    typedef DWORD* (__fastcall *fn_desc)(void*);
    fn_desc get_desc = (fn_desc)vt[1];
    DWORD *desc = get_desc(body);
    fprintf(logf, "Desc 0x%08x\n", (DWORD)desc); fflush(logf);

    /* Create a minimal BitStream */
    /* From FUN_1005c700: [0]=buf_ptr, [1]=?, [2]=pos, [3]=capacity, [4]=?, [5]=max */
    BYTE buf[4096];
    memset(buf, 0, sizeof(buf));
    DWORD bitstream[16];
    memset(bitstream, 0, sizeof(bitstream));
    bitstream[0] = (DWORD)buf;
    bitstream[3] = sizeof(buf);  /* capacity */
    bitstream[5] = sizeof(buf);  /* max capacity */

    /* Call FUN_101a9930 */
    /* __thiscall: ecx=body, [esp+4]=bitstream, [esp+8]=version_or_null */
    typedef int (__thiscall *fn_ser)(void*, DWORD*, void*);
    fn_ser ser = (fn_ser)(base + 0x1a9930);

    fprintf(logf, "Calling serialize...\n"); fflush(logf);
    int r = ser(body, bitstream, NULL);
    fprintf(logf, "Result: %d, traces: %d\n", r, trace_count); fflush(logf);

    /* Dump output */
    DWORD pos = bitstream[2];
    DWORD bits = bitstream[1];
    fprintf(logf, "pos=%u bits=%u\n", pos, bits);
    int total = pos + (bits > 0 ? 1 : 0);
    fprintf(logf, "Output (%d bytes): ", total);
    for (int i = 0; i < total && i < 32; i++) fprintf(logf, "%02x", buf[i]);
    fprintf(logf, "\n");

    fclose(logf);
    FreeLibrary(h);
    return 0;
}
