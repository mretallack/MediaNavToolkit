/*
 * r7_nngine_harness.c — Load nngine.dll and try to call NngineStart
 * to observe the wire protocol header construction.
 *
 * We want to understand byte 15 of the header.
 */
#include <stdio.h>
#include <windows.h>

typedef int (*NngineStartFunc)(void);
typedef int (*NngineStopFunc)(void);
typedef int (*NngineIsRunningFunc)(void);
typedef int (*NngineAttachConfigFunc)(const char*);

int main() {
    printf("Loading nngine.dll...\n");
    
    /* Need to be in the same directory as the DLL for dependencies */
    SetDllDirectoryA("Z:\\work\\extracted");
    SetCurrentDirectoryA("Z:\\work\\extracted");
    
    HMODULE h = LoadLibraryA("Z:\\work\\extracted\\nngine.dll");
    if (!h) {
        printf("Failed to load nngine.dll: error %lu\n", GetLastError());
        return 1;
    }
    printf("nngine.dll loaded at %p\n", h);
    
    /* Get exports */
    NngineStartFunc start = (NngineStartFunc)GetProcAddress(h, "NngineStart");
    NngineStopFunc stop = (NngineStopFunc)GetProcAddress(h, "NngineStop");
    NngineIsRunningFunc running = (NngineIsRunningFunc)GetProcAddress(h, "NngineIsRunning");
    NngineAttachConfigFunc config = (NngineAttachConfigFunc)GetProcAddress(h, "NngineAttachConfig");
    
    printf("NngineStart: %p\n", start);
    printf("NngineStop: %p\n", stop);
    printf("NngineIsRunning: %p\n", running);
    printf("NngineAttachConfig: %p\n", config);
    
    if (!start) {
        printf("NngineStart not found\n");
        FreeLibrary(h);
        return 1;
    }
    
    /* Check if it's already running */
    if (running) {
        int r = running();
        printf("IsRunning: %d\n", r);
    }
    
    /* Try to read the stored credentials from the registry
     * The Toolbox stores Code/Secret in the Windows registry */
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_CURRENT_USER, 
        "Software\\NNG\\DaciaAutomotive\\DaciaToolbox", 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        printf("\nRegistry key found!\n");
        char value[256];
        DWORD size, type;
        
        /* Enumerate all values */
        DWORD index = 0;
        char name[256];
        DWORD nameSize;
        while (1) {
            nameSize = sizeof(name);
            size = sizeof(value);
            result = RegEnumValueA(hKey, index, name, &nameSize, NULL, &type, (BYTE*)value, &size);
            if (result != ERROR_SUCCESS) break;
            printf("  %s (type=%lu, size=%lu): ", name, type, size);
            if (type == REG_SZ) {
                printf("%s\n", value);
            } else if (type == REG_BINARY) {
                int i;
                for (i = 0; i < (int)size && i < 32; i++) printf("%02x", (unsigned char)value[i]);
                printf("\n");
            } else if (type == REG_DWORD) {
                printf("%lu\n", *(DWORD*)value);
            } else {
                printf("(type %lu)\n", type);
            }
            index++;
        }
        RegCloseKey(hKey);
    } else {
        printf("\nRegistry key not found (error %ld)\n", result);
        /* Try other possible paths */
        const char *paths[] = {
            "Software\\NNG",
            "Software\\DaciaAutomotive",
            "Software\\NaviExtras",
            "Software\\iGO",
            NULL
        };
        int i;
        for (i = 0; paths[i]; i++) {
            result = RegOpenKeyExA(HKEY_CURRENT_USER, paths[i], 0, KEY_READ, &hKey);
            if (result == ERROR_SUCCESS) {
                printf("Found: HKCU\\%s\n", paths[i]);
                RegCloseKey(hKey);
            }
        }
    }
    
    /* Also check for .sav files in the extracted directory */
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("Z:\\work\\extracted\\*.sav", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            printf("Found .sav: %s (%lu bytes)\n", fd.cFileName, fd.nFileSizeLow);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    
    FreeLibrary(h);
    return 0;
}
