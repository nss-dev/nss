/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
** prshma.h -- NSPR Anonymous Shared Memory
**
**
*/

#include "primpl.h"

extern PRLogModuleInfo* _pr_shma_lm;

#if defined(XP_UNIX)
/* defined in pr/src/md/unix/uxshm.c */
#elif defined(WIN32)
/* defined in pr/src/md/windows/w32shm.c */
#else
extern PRFileMap* _PR_MD_OPEN_ANON_FILE_MAP(const char* dirName, PRSize size,
                                            PRFileMapProtect prot) {
  MPR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
  return NULL;
}
extern PRStatus _PR_MD_EXPORT_FILE_MAP_AS_STRING(PRFileMap* fm, PRSize bufSize,
                                                 char* buf) {
  MPR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
  return PR_FAILURE;
}
extern PRFileMap* _PR_MD_IMPORT_FILE_MAP_FROM_STRING(const char* fmstring) {
  MPR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
  return NULL;
}
#endif

/*
** MPR_OpenAnonFileMap() -- Creates an anonymous file-mapped shared memory
**
*/
PR_IMPLEMENT(PRFileMap*)
MPR_OpenAnonFileMap(const char* dirName, PRSize size, PRFileMapProtect prot) {
  return (_PR_MD_OPEN_ANON_FILE_MAP(dirName, size, prot));
} /* end MPR_OpenAnonFileMap() */

/*
** MPR_ProcessAttrSetInheritableFileMap() -- Prepare FileMap for export
**   to my children processes via MPR_CreateProcess()
**
**
*/
PR_IMPLEMENT(PRStatus)
MPR_ProcessAttrSetInheritableFileMap(PRProcessAttr* attr, PRFileMap* fm,
                                    const char* shmname) {
  MPR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
  return (PR_FAILURE);
} /* end MPR_ProcessAttrSetInheritableFileMap() */

/*
** MPR_GetInheritedFileMap() -- Import a PRFileMap previously exported
**   by my parent process via MPR_CreateProcess()
**
*/
PR_IMPLEMENT(PRFileMap*)
MPR_GetInheritedFileMap(const char* shmname) {
  PRFileMap* fm = NULL;
  MPR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
  return (fm);
} /* end PR_GetInhteritedFileMap() */

/*
** MPR_ExportFileMapAsString() -- Creates a string identifying a PRFileMap
**
*/
PR_IMPLEMENT(PRStatus)
MPR_ExportFileMapAsString(PRFileMap* fm, PRSize bufSize, char* buf) {
  return (_PR_MD_EXPORT_FILE_MAP_AS_STRING(fm, bufSize, buf));
} /* end MPR_ExportFileMapAsString() */

/*
** MPR_ImportFileMapFromString() -- Creates a PRFileMap from the identifying
*string
**
**
*/
PR_IMPLEMENT(PRFileMap*)
MPR_ImportFileMapFromString(const char* fmstring) {
  return (_PR_MD_IMPORT_FILE_MAP_FROM_STRING(fmstring));
} /* end MPR_ImportFileMapFromString() */
/* end prshma.c */
