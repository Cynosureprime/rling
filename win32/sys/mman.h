/*
 * sys/mman.h compatibility shim for MinGW/Windows
 * Maps POSIX mmap/munmap to Windows API (CreateFileMapping/MapViewOfFile)
 */
#ifndef _SYS_MMAN_H_WIN32
#define _SYS_MMAN_H_WIN32

#include <windows.h>
#include <io.h>
#include <stdint.h>

#define PROT_READ     0x1
#define PROT_WRITE    0x2

#define MAP_SHARED    0x01
#define MAP_PRIVATE   0x02
#define MAP_FILE      0x00
#define MAP_FAILED    ((void *)-1)

/* MAP_POPULATE is Linux-specific; no-op on Windows */

static inline void *mmap(void *addr, size_t length, int prot, int flags,
                         int fd, int64_t offset)
{
    DWORD flProtect;
    DWORD dwAccess;
    HANDLE hMap;
    void *ptr;
    HANDLE hFile;

    (void)addr; /* hint ignored */

    if (prot & PROT_WRITE) {
        flProtect = PAGE_READWRITE;
        dwAccess = FILE_MAP_WRITE;
    } else {
        flProtect = PAGE_READONLY;
        dwAccess = FILE_MAP_READ;
    }

    if (flags & MAP_PRIVATE) {
        flProtect = PAGE_WRITECOPY;
        dwAccess = FILE_MAP_COPY;
    }

    hFile = (HANDLE)_get_osfhandle(fd);
    if (hFile == INVALID_HANDLE_VALUE)
        return MAP_FAILED;

    hMap = CreateFileMapping(hFile, NULL, flProtect,
                             (DWORD)((offset + length) >> 32),
                             (DWORD)((offset + length) & 0xFFFFFFFF),
                             NULL);
    if (!hMap)
        return MAP_FAILED;

    ptr = MapViewOfFile(hMap, dwAccess,
                        (DWORD)(offset >> 32),
                        (DWORD)(offset & 0xFFFFFFFF),
                        length);
    CloseHandle(hMap);

    if (!ptr)
        return MAP_FAILED;

    return ptr;
}

static inline int munmap(void *addr, size_t length)
{
    (void)length;
    return UnmapViewOfFile(addr) ? 0 : -1;
}

#endif /* _SYS_MMAN_H_WIN32 */
