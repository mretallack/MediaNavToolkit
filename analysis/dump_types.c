#include <windows.h>
#include <stdio.h>

int main() {
    HMODULE h = LoadLibraryA("C:\\nngine.dll");
    if (!h) { printf("FAIL: %lu\n", GetLastError()); return 1; }

    DWORD base = (DWORD)h;
    printf("BASE: 0x%08x\n", base);

    /* The body object's inner vtable returns descriptor at base + 0x1030de08 - 0x10000000 */
    /* But with ASLR, we need to use the actual base */
    /* Descriptor at RVA 0x30DE08 */
    DWORD *desc = (DWORD*)(base + 0x30DE08);
    
    /* The descriptor is a linked list. First node is at desc[1] (offset 4) */
    /* But desc itself might be the field array, not a header */
    /* Let me dump the area around the descriptor */
    
    printf("\nDescriptor area (RVA 0x30DE08):\n");
    BYTE *p = (BYTE*)(base + 0x30DE08);
    for (int i = 0; i < 96; i += 4) {
        printf("  +0x%02x: 0x%08x\n", i, *(DWORD*)(p + i));
    }
    
    /* The body object constructor is at RVA 0x0B4A30 */
    /* It sets vtable at param_1[0] and param_1[10] */
    /* vtable[1] returns the descriptor */
    /* Let me call vtable[1] to get the actual descriptor */
    
    /* Actually, let me just dump the ENTIRE BSS with more context */
    /* Focus on the linked list nodes */
    
    /* From the assembly, the linked list node structure is: */
    /* [next:4][func:4][field_array:4][field_count:2][parent_idx:2][...] */
    /* The field_array contains 24-byte entries */
    
    /* Let me scan BSS for linked list nodes */
    /* A node has: [ptr][ptr][ptr][small_int:2][small_int:2] */
    
    BYTE *bss = (BYTE*)(base + 0x314200);
    DWORD bss_size = 0x1A1F8;
    DWORD text_start = base + 0x1000;
    DWORD text_end = base + 0x2ACE00;
    DWORD rdata_start = base + 0x2AE000;
    DWORD rdata_end = base + 0x30A200;
    
    printf("\nScanning for linked list nodes...\n");
    int found = 0;
    for (DWORD i = 0; i + 16 <= bss_size; i += 4) {
        DWORD *node = (DWORD*)(bss + i);
        DWORD next = node[0];
        DWORD func = node[1];
        DWORD farr = node[2];
        short fcount = *(short*)(bss + i + 12);
        short pidx = *(short*)(bss + i + 14);
        
        /* Check if this looks like a node: */
        /* next is 0 or points to BSS */
        /* func points to .text */
        /* field_array points to .rdata */
        /* field_count is small positive */
        if (!(next == 0 || (next >= (DWORD)(base + 0x314200) && next < (DWORD)(base + 0x32C400)))) continue;
        if (!(func >= text_start && func < text_end)) continue;
        if (!(farr >= rdata_start && farr < rdata_end)) continue;
        if (fcount < 0 || fcount > 100) continue;
        
        DWORD node_va = (DWORD)(bss + i);
        printf("\n  Node at 0x%08x: next=0x%08x func=0x%08x fields=%d parent=%d\n",
               node_va, next, func, fcount, pidx);
        
        /* Read field entries (24 bytes each) */
        for (int j = 0; j < fcount && j < 20; j++) {
            BYTE *fe = (BYTE*)(farr + j * 24);
            DWORD name_ptr = *(DWORD*)(fe + 0);
            DWORD type_ptr = *(DWORD*)(fe + 16);
            DWORD ser_func = *(DWORD*)(fe + 20);
            DWORD version = *(DWORD*)(fe + 12);
            BYTE flag = fe[22]; /* flag at offset 0x16 */
            
            /* Get field name */
            char *name = "?";
            if (name_ptr >= rdata_start && name_ptr < rdata_end) {
                name = (char*)name_ptr;
            }
            
            /* Get type_id from type object */
            int type_id = -1;
            if (type_ptr >= (DWORD)(base + 0x314200) && type_ptr < (DWORD)(base + 0x32C400)) {
                type_id = *(BYTE*)(type_ptr + 4);
            }
            
            printf("    [%2d] %-30s type=%d ver=0x%08x flag=%d\n",
                   j, name, type_id, version, flag);
        }
        
        found++;
        if (found > 30) break;
    }
    
    printf("\nFound %d nodes\n", found);
    FreeLibrary(h);
    return 0;
}
