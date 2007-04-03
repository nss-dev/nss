/*
 * license
 */


#ifndef SFTKDBT_H
#define SFTKDBT_H 1
typedef struct SFTKDBHandleStr SFTKDBHandle;

typedef enum {
   SDB_SHARED,
   SDB_LOADABLE,
   SDB_LEGACY,
   SDB_MULTIACCESS
} SDBType;

#endif
