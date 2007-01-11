/*
 * license
 */
#include "pkcs11i.h"

/* parsing functions */
char * sftk_argFetchValue(char *string, int *pcount);
char * sftk_getSecmodName(char *param, const char **dbType, char **appName, char **filename,PRBool *rw);
char *sftk_argStrip(char *c);
CK_RV sftk_parseParameters(char *param, sftk_parameters *parsed, PRBool isFIPS);
void sftk_freeParams(sftk_parameters *params);
const char *sftk_EvaluateConfigDir(const char *configdir, const char **dbType, char **app);
char * sftk_argGetParamValue(char *paramName,char *parameters);



