// From https://gist.github.com/rdp/5e49fbbbcaca5a299a67b5daad4a2a3d.

#include "..\..\deps\objc4\runtime\objc-private.h"

#define PATH_MAX 4096

int dladdr (const void *addr, Dl_info *info)
{
   // only returns filename, FWIW.
   TCHAR  tpath[PATH_MAX];
   char  *path;
   char  *tmp;
   size_t length;
   int    ret = 0;

   if (!info)
     return 0;

   ret = GetModuleFileName(NULL, (LPTSTR)&tpath, PATH_MAX);
   if (!ret)
     return 0;

   path = tpath;

   length = strlen (path);
   if (length >= PATH_MAX)
     {
       length = PATH_MAX - 1;
       path[PATH_MAX - 1] = '\0';
     }

   /* replace '/' by '\' */
   tmp = path;
   while (*tmp)
     {
        if (*tmp == '/') *tmp = '\\';
        tmp++;
     }

   memcpy ((void *)info->dli_fname, path, length + 1);
   info->dli_fbase = NULL;
   info->dli_sname = NULL;
   info->dli_saddr = NULL;
   return 1;
}
