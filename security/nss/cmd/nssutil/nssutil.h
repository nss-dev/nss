
#include "nsspkit.h"
#include "cmdutil.h"

#define NSSUTIL_VERSION_STRING "nssutil version 0.1"

extern char *progName;

PRStatus ListModules(CMDRunTimeData *rtData);

#if 0
PRStatus ListSlots(CMDRunTimeData *rtData);
#endif

PRStatus DumpModuleInfo(char *moduleName, CMDRunTimeData *rtData);

PRStatus DumpSlotInfo(char *slotName, NSSTrustDomain *td,
                      CMDRunTimeData *rtData);
PRStatus 
DumpTokenInfo(char *tokenName, NSSTrustDomain *td, CMDRunTimeData *rtData);

