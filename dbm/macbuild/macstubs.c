
// Hack to define a never-called routine from libdbm
#include "mcom_db.h"

DBFILE_PTR mkstemp(const char* /*path*/)
{
	return NO_FILE;
}
