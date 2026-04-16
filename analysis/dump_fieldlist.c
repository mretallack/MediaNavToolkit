#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { printf("FAIL: %lu\n", GetLastError()); return 1; }
    DWORD base = (DWORD)h;
    printf("BASE: 0x%08x\n", base);

    /* The body object constructor is at RVA 0x0B4A30 */
    /* It's __fastcall, takes param_1 (ecx) = pointer to object buffer */
    /* The object is about 0x74 bytes (from the constructor's field init) */
    typedef void* (__fastcall *fn_ctor)(void *obj);
    fn_ctor body_ctor = (fn_ctor)(base + 0x0B4A30);

    /* Allocate the body object */
    BYTE body_obj[256];
    memset(body_obj, 0, sizeof(body_obj));

    printf("Calling body constructor at 0x%08x...\n", (DWORD)body_ctor);
    void *result = body_ctor(body_obj);
    printf("Constructor returned: 0x%08x\n", (DWORD)result);

    /* The body object now has two vtables: */
    /* body_obj[0] = outer vtable (at RVA 0x2BB1B4) */
    /* body_obj[0x28] = inner vtable (at RVA 0x2BB1AC) */
    DWORD outer_vt = *(DWORD*)(body_obj + 0);
    DWORD inner_vt = *(DWORD*)(body_obj + 0x28);
    printf("Outer vtable: 0x%08x (expected ~0x%08x)\n", outer_vt, base + 0x2BB1B4);
    printf("Inner vtable: 0x%08x (expected ~0x%08x)\n", inner_vt, base + 0x2BB1AC);

    /* Call inner vtable[1] to get the descriptor */
    /* vtable[1] is at inner_vt + 4 */
    typedef DWORD* (__fastcall *fn_get_desc)(void *obj);
    DWORD *inner_vt_ptr = (DWORD*)inner_vt;
    fn_get_desc get_desc = (fn_get_desc)inner_vt_ptr[1];
    printf("get_desc func: 0x%08x\n", (DWORD)get_desc);

    /* The get_desc function returns a pointer to the descriptor */
    /* It's called with ecx = &body_obj[0x28] (the inner sub-object) */
    DWORD *desc = get_desc(body_obj + 0x28);
    printf("Descriptor: 0x%08x\n", (DWORD)desc);

    if (desc) {
        /* The descriptor is a type object with: */
        /* [0] = vtable */
        /* [4] = field_array_ptr or linked_list_head */
        /* Read the descriptor structure */
        printf("\nDescriptor contents:\n");
        for (int i = 0; i < 8; i++) {
            printf("  [%d] 0x%08x\n", i, desc[i]);
        }

        /* The compound serializer reads desc[1] as the field list */
        /* Then calls FUN_101a9da0 which iterates a linked list */
        /* The linked list node: [next:4][func:4][field_array:4][count:2][parent:2] */

        /* desc itself might be the first node of the linked list */
        /* Or desc[1] might point to the first node */

        /* Let me follow the linked list starting from desc */
        printf("\nFollowing linked list from descriptor...\n");
        DWORD *node = desc;
        int depth = 0;
        while (node && depth < 20) {
            DWORD next = node[0];
            printf("  Node 0x%08x: [0]=0x%08x [1]=0x%08x [2]=0x%08x",
                   (DWORD)node, node[0], node[1], node[2]);
            short count = *(short*)((BYTE*)node + 12);
            short pidx = *(short*)((BYTE*)node + 14);
            printf(" count=%d pidx=%d\n", count, pidx);

            /* If count > 0, read field entries */
            DWORD field_arr = node[2];
            if (count > 0 && field_arr > base && field_arr < base + 0x400000) {
                for (int i = 0; i < count && i < 10; i++) {
                    BYTE *fe = (BYTE*)(field_arr + i * 24);
                    DWORD name_ptr = *(DWORD*)(fe + 0);
                    DWORD type_obj = *(DWORD*)(fe + 16);
                    char *name = "?";
                    if (name_ptr > base && name_ptr < base + 0x400000) {
                        /* Check if it's a readable string */
                        char *s = (char*)name_ptr;
                        if (s[0] >= 0x20 && s[0] <= 0x7e) name = s;
                    }
                    int tid = -1;
                    if (type_obj > base && type_obj < base + 0x400000) {
                        tid = *((BYTE*)type_obj + 4);
                    }
                    printf("    [%d] %-30s type_id=%d\n", i, name, tid);
                }
            }

            /* Follow next pointer */
            if (next == 0 || next == (DWORD)node) break;
            if (next < base || next > base + 0x400000) break;
            node = (DWORD*)next;
            depth++;
        }
    }

    FreeLibrary(h);
    return 0;
}
