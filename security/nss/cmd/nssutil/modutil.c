
#include "nssutil.h"
#include "nssdev.h"
#include "nsspki.h"

#define PRINT_FLAG(file, desc, flag) \
    PR_fprintf(file, "  %-25s %s\n", desc, (flag)?"Yes":"No");

PRStatus 
ListModules(CMDRunTimeData *rtData)
{
    NSSModule **mp, **modules;
    NSSModuleInfo info;

    modules = NSS_GetLoadedModules();
    if (!modules) {
	fprintf(stderr, "No modules are loaded.\n");
	return PR_FAILURE;
    }
    for (mp = modules; *mp; mp++) {
	NSSModule_GetInfo(*mp, &info);
	printf("Module: %s\n", info.name);
    }

    NSSModuleArray_Destroy(modules);
    return PR_SUCCESS;
}

#define IF_STRING(str) (str) ? (str) : "<NONE>"

PRStatus 
DumpModuleInfo(char *moduleName, CMDRunTimeData *rtData)
{
    PRUint32 i;
    NSSModule *module;
    NSSModuleInfo info;
    CMDFileData *fData = &rtData->output;

    module = NSS_FindModuleByName(moduleName);
    if (!module) {
	fprintf(stderr, "No module named \"%s\" is loaded.\n", moduleName);
	return PR_FAILURE;
    }

    NSSModule_GetInfo(module, &info);

    PR_fprintf(fData->file, "\n");
    PR_fprintf(fData->file, "\n");

    PR_fprintf(fData->file, "Module Name: \"%s\"\n", IF_STRING(info.name));
    PR_fprintf(fData->file, "\n");
    PR_fprintf(fData->file, "  %-20s %s\n", "Library File:", 
                                            IF_STRING(info.libraryName));
    PR_fprintf(fData->file, "\n");

    PR_fprintf(fData->file, "  %-20s %s\n", "Manufacturer ID:", 
                                            IF_STRING(info.manufacturerID));
    PR_fprintf(fData->file, "  %-20s %s\n", "Library Description:", 
                                            IF_STRING(info.libraryDescription));
    PR_fprintf(fData->file, "  %-20s %d.%d\n", "Library Version:", 
                                               info.libraryVersion.major, 
                                               info.libraryVersion.minor);
    PR_fprintf(fData->file, "\n");

    PR_fprintf(fData->file, "  %-20s %d.%d\n", "Cryptoki Version:", 
                                               info.cryptokiVersion.major, 
                                               info.cryptokiVersion.minor);
    PR_fprintf(fData->file, "  %-20s ", "Flags:");
    PR_fprintf(fData->file, "%s", (info.isThreadSafe) ? "threadsafe " : "");
    PR_fprintf(fData->file, "%s", (info.isInternal) ? "internal " : "");
    PR_fprintf(fData->file, "%s", (info.isFIPS) ? "FIPS " : "");
    PR_fprintf(fData->file, "%s", (info.isCritical) ? "critical" : "");
    PR_fprintf(fData->file, "\n");
    PR_fprintf(fData->file, "\n");

    PR_fprintf(fData->file, "  Number of slots: %d\n", info.numSlots);
    for (i=0; i<info.numSlots; i++) {
	PR_fprintf(fData->file, "    Slot %d: \"%s\"\n", i, 
	                             IF_STRING(info.slotNames[i]));
    }
    PR_fprintf(fData->file, "\n");
    PR_fprintf(fData->file, "\n");

    NSSModule_Destroy(module);
    return PR_FAILURE;
}

#if 0
PRStatus 
ListSlots(NSSTrustDomain *td, CMDRunTimeData *rtData)
{
    NSSModule **mp, **modules;
    NSSModuleInfo info;

    modules = NSS_GetLoadedModules();
    if (!modules) {
	fprintf(stderr, "No modules are loaded.\n");
	return PR_FAILURE;
    }
    for (mp = modules; *mp; mp++) {
	NSSModule_GetInfo(*mp, &info);
	printf("Module: %s\n", info.name);
    }

    NSSModuleArray_Destroy(modules);
    return PR_SUCCESS;
}
#endif

PRStatus 
DumpSlotInfo(char *slotName, NSSTrustDomain *td, CMDRunTimeData *rtData)
{
    NSSSlot *slot;
    NSSSlotInfo info;
    CMDFileData *fData = &rtData->output;

    slot = NSSTrustDomain_FindSlotByName(td, slotName);
    if (!slot) {
	fprintf(stderr, "No slot named \"%s\" is present.\n", slotName);
	return PR_FAILURE;
    }

    NSSSlot_GetInfo(slot, &info);

    PR_fprintf(fData->file, "\n");
    PR_fprintf(fData->file, "\n");

    PR_fprintf(fData->file, "Slot Name: \"%s\"\n", IF_STRING(info.name));
    PR_fprintf(fData->file, "\n");

#if 0
    PR_fprintf(fData->file, "  %-20s %s\n", "Manufacturer ID:", 
                                            IF_STRING(info.manufacturerID));
    PR_fprintf(fData->file, "  %-20s %s\n", "Description:", 
                                            IF_STRING(info.description));
    PR_fprintf(fData->file, "  %-20s %d.%d\n", "Hardware Version:", 
                                               info.hardwareVersion.major, 
                                               info.hardwareVersion.minor);
    PR_fprintf(fData->file, "  %-20s %d.%d\n", "Firmware Version:", 
                                               info.firmwareVersion.major, 
                                               info.firmwareVersion.minor);
    PR_fprintf(fData->file, "\n");
#endif

    PR_fprintf(fData->file, "  %-20s \"%s\"\n", "Module Name:", 
                                            IF_STRING(info.moduleName));
    PR_fprintf(fData->file, "  %-20s \"%s\"\n", "Token Name:", 
                                            IF_STRING(info.tokenName));
    PR_fprintf(fData->file, "\n");

    PRINT_FLAG(fData->file, "Hardware:", info.isHardware);
    PRINT_FLAG(fData->file, "Token Removable:", info.isTokenRemovable);
    PRINT_FLAG(fData->file, "Token Present:", info.isTokenPresent);
    PR_fprintf(fData->file, "\n");
    PR_fprintf(fData->file, "\n");

    NSSSlot_Destroy(slot);
    return PR_FAILURE;
}

PRStatus 
DumpTokenInfo(char *tokenName, NSSTrustDomain *td, CMDRunTimeData *rtData)
{
    NSSToken *token;
    NSSTokenInfo info;
    CMDFileData *fData = &rtData->output;

    token = NSSTrustDomain_FindTokenByName(td, tokenName);
    if (!token) {
	fprintf(stderr, "No token named \"%s\" is present.\n", tokenName);
	return PR_FAILURE;
    }

    NSSToken_GetInfo(token, &info);

    PR_fprintf(fData->file, "\n");
    PR_fprintf(fData->file, "\n");

    PR_fprintf(fData->file, "Token Name: \"%s\"\n", IF_STRING(info.name));
    PR_fprintf(fData->file, "\n");

#if 0
    PR_fprintf(fData->file, "  %-20s %s\n", "Manufacturer ID:", 
                                            IF_STRING(info.manufacturerID));
    PR_fprintf(fData->file, "  %-20s %s\n", "Description:", 
                                            IF_STRING(info.description));
    PR_fprintf(fData->file, "  %-20s %d.%d\n", "Hardware Version:", 
                                               info.hardwareVersion.major, 
                                               info.hardwareVersion.minor);
    PR_fprintf(fData->file, "  %-20s %d.%d\n", "Firmware Version:", 
                                               info.firmwareVersion.major, 
                                               info.firmwareVersion.minor);
    PR_fprintf(fData->file, "\n");
#endif

    PRINT_FLAG(fData->file, "Has RNG:", info.hasRNG);
    PRINT_FLAG(fData->file, "Has Clock:", info.hasClock);
    PRINT_FLAG(fData->file, "Has Protected Auth Path:", 
                            info.hasProtectedAuthPath);
    PRINT_FLAG(fData->file, "Write Protected:", info.isWriteProtected);
    PRINT_FLAG(fData->file, "Login Required:", info.isLoginRequired);
    PRINT_FLAG(fData->file, "User PIN Initialized:", info.isPINInitialized);
    PRINT_FLAG(fData->file, "Supports Dual Crypto:", info.supportsDualCrypto);
    PR_fprintf(fData->file, "\n");
    PR_fprintf(fData->file, "\n");

    NSSToken_Destroy(token);
    return PR_FAILURE;
}

