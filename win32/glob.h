/*
 * glob.h compatibility shim for MinGW/Windows
 * Minimal implementation using FindFirstFileA/FindNextFileA
 */
#ifndef _GLOB_H_WIN32
#define _GLOB_H_WIN32

#include <windows.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t gl_pathc;
    char **gl_pathv;
    size_t gl_offs;
} glob_t;

static inline int glob(const char *pattern, int flags,
                       int (*errfunc)(const char *, int), glob_t *pglob)
{
    WIN32_FIND_DATAA fd;
    HANDLE hFind;
    size_t cap = 64;
    char dirprefix[MAX_PATH] = "";
    const char *lastslash;

    (void)flags;
    (void)errfunc;

    pglob->gl_pathc = 0;
    pglob->gl_pathv = (char **)malloc(cap * sizeof(char *));
    if (!pglob->gl_pathv) return -1;

    /* extract directory prefix from pattern */
    lastslash = strrchr(pattern, '/');
    if (!lastslash) lastslash = strrchr(pattern, '\\');
    if (lastslash) {
        size_t len = lastslash - pattern + 1;
        if (len >= MAX_PATH) len = MAX_PATH - 1;
        memcpy(dirprefix, pattern, len);
        dirprefix[len] = '\0';
    }

    hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return -1;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        if (pglob->gl_pathc >= cap) {
            cap *= 2;
            char **tmp = (char **)realloc(pglob->gl_pathv, cap * sizeof(char *));
            if (!tmp) { FindClose(hFind); return -1; }
            pglob->gl_pathv = tmp;
        }
        size_t plen = strlen(dirprefix) + strlen(fd.cFileName) + 1;
        char *path = (char *)malloc(plen);
        if (!path) { FindClose(hFind); return -1; }
        strcpy(path, dirprefix);
        strcat(path, fd.cFileName);
        pglob->gl_pathv[pglob->gl_pathc++] = path;
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return 0;
}

static inline void globfree(glob_t *pglob)
{
    size_t i;
    for (i = 0; i < pglob->gl_pathc; i++)
        free(pglob->gl_pathv[i]);
    free(pglob->gl_pathv);
    pglob->gl_pathv = NULL;
    pglob->gl_pathc = 0;
}

#endif /* _GLOB_H_WIN32 */
