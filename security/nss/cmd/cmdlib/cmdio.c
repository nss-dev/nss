/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

#include <string.h>
#include <ctype.h>

#include "cmdutil.h"

/* get error from NSPR */
#define FILE_ERROR(file) \
  fprintf(stderr, "Failed to open %s\n", file); \
  return PR_FAILURE;

static CMDFileMode
get_file_mode(char *mode)
{
    if (strcmp(mode, "ascii") == 0) {
	return CMDFileMode_Ascii;
    } else if (strcmp(mode, "binary") == 0) {
	return CMDFileMode_Binary;
    } else if (strcmp(mode, "pretty-print") == 0) {
	return CMDFileMode_PrettyPrint;
    } else if (strcmp(mode, "hex") == 0) {
	return CMDFileMode_Hex;
    } else if (strcmp(mode, "hex-with-space") == 0 ||
               strcmp(mode, "hexwspc") == 0) {
	return CMDFileMode_HexWithSpace;
    } else if (strcmp(mode, "hex-converted") == 0) {
	return CMDFileMode_HexConvertedWithSpace;
    } else {
	fprintf(stderr, "File mode \"%s\" not recognized\n", mode);
	return -1;
    }
}

PRStatus
CMD_SetRunTimeData(char *inputFileName, char *input, char *inMode,
                   char *outputFileName, char *outMode,
                   CMDRunTimeData *rtData)
{
    CMDFileData *fileData;
    /* Get input file data */
    fileData = &rtData->input;
    memset(fileData, 0, sizeof (*fileData));
    if (inputFileName) {
	fileData->name = inputFileName;
	fileData->file = PR_Open(fileData->name, PR_RDONLY, 0660);
	if (!fileData->file) {
	    FILE_ERROR(fileData->name);
	}
    } else if (input) {
	fileData->str = input;
    } else {
	fileData->name = NULL;
	fileData->file = PR_STDIN;
    }
    fileData->mode = get_file_mode(inMode);
    if (fileData->mode == -1) {
	CMD_FinishRunTimeData(rtData);
	return PR_FAILURE;
    }
    /* Get output file data */
    fileData = &rtData->output;
    memset(fileData, 0, sizeof (*fileData));
    if (outputFileName) {
	fileData->name = outputFileName;
	fileData->file = PR_Open(fileData->name, 
	                         PR_WRONLY | PR_CREATE_FILE, 0660);
	if (!fileData->file) {
	    FILE_ERROR(fileData->name);
	}
    } else {
	fileData->name = NULL;
	fileData->file = PR_STDOUT;
    }
    fileData->mode = get_file_mode(outMode);
    if (fileData->mode == -1) {
	CMD_FinishRunTimeData(rtData);
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

/* also allow for deletion */
void
CMD_FinishRunTimeData(CMDRunTimeData *rtData)
{
    if (rtData->input.name) {
	PR_Close(rtData->input.file);
    }
    if (rtData->output.name) {
	PR_Close(rtData->output.file);
    }
}

static PRStatus
byte_from_str(unsigned char *byteval, unsigned char *str)
{
    int i;
    unsigned char offset;
    *byteval = 0;
    if (!str || !str[1]) {
	return PR_FAILURE;
    }
    for (i=0; i<2; i++) {
	if (str[i] >= '0' && str[i] <= '9') {
	    offset = str[i] - '0';
	    *byteval |= offset << 4*(1-i);
	} else if (str[i] >= 'a' && str[i] <= 'f') {
	    offset = str[i] - 'a';
	    *byteval |= (offset + 10) << 4*(1-i);
	} else if (str[i] >= 'A' && str[i] <= 'F') {
	    offset = str[i] - 'A';
	    *byteval |= (offset + 10) << 4*(1-i);
	} else {
	    return PR_FAILURE;
	}
    }
    return PR_SUCCESS;
}

NSSItem *
CMD_ConvertHexData(char *stream, unsigned int streamLen, CMDFileMode *mode)
{
    int kind;
    int guess_len, actual_len;
    unsigned char *output = NULL;
    PRStatus status;
    NSSItem *rvIt;
    /* either space-delimited stream YY YY ... or pure stream YYY... */
    guess_len = strlen(stream); 
    if (guess_len >= 3) {
	if (stream[0] == '0' && 
	    (stream[1] == 'x' || stream[1] == 'X')) {
	    /* space-delimited stream 0xYY 0xYY ...,
	     * 5 characters in the stream represent one byte 
	     */
	    *mode = CMDFileMode_HexConvertedWithSpace;
	    guess_len = guess_len / 5 + 1;
	} else if (isspace(stream[2])) {
	    /* space-delimited stream YY YY ..., 3 char/byte */
	    *mode = CMDFileMode_HexWithSpace;
	    guess_len = guess_len / 3 + 1;
	} else {
	    /* stream YYYY..., 2 char/byte */
	    guess_len = guess_len / 2 + 1;
	}
    }
    output = malloc(guess_len);
    if (!output) {
	fprintf(stderr, "malloc failed in CMD_ConvertHexStream.\n");
	return NULL;
    }
    actual_len = 0;
    while (*stream) {
	switch (kind) {
	case CMDFileMode_HexConvertedWithSpace:
	    /* sanity checking */
	    if (!stream || *stream++ != '0') {
		goto failure;
	    }
	    if (!stream || *stream != 'x' || *stream != 'X') {
		goto failure;
	    }
	    stream++;
	    /* fall through */
	default:
	    /* get the byte */
	    status = byte_from_str(&output[actual_len], stream);
	    if (status != PR_SUCCESS) {
		goto failure;
	    }
	    actual_len++;
	    stream += 2;
	    /* more remaining, skip trailing space and keep going */
	    if (stream && isspace(*stream)) {
		stream++;
	    }
	}
    }
    rvIt = NSSItem_Create(NULL, NULL, actual_len, output);
    free(output);
    return rvIt;
failure:
    fprintf(stderr, "Inproperly formatted input string");
    if (stream) {
	fprintf(stderr, " at %s", stream);
    }
    fprintf(stderr, "\n");
    if (output) {
	free(output);
    }
    return NULL;
}

unsigned char *
CMD_ReadFile(PRFileDesc *file, int *flen)
{
    int nb, len;
    unsigned char readBuf[256];
    unsigned char *writeBuf = NULL;
    len = 0;
    while ((nb = PR_Read(file, readBuf, sizeof readBuf)) > 0) {
	if (!writeBuf) {
	    writeBuf = malloc(nb);
	} else {
	    writeBuf = realloc(writeBuf, len + nb);
	}
	memcpy(writeBuf + len, readBuf, nb);
	len += nb;
    }
    return writeBuf;
}

NSSItem *
CMD_GetDataFromBuffer(unsigned char *buffer, unsigned int bufLen, 
                      CMDFileMode *mode)
{
    NSSItem *rvIt = NULL;
    /* Convert the input to binary */
    if (*mode == CMDFileMode_Hex) {
	/* from one of the hex flavors, mode may change */
	rvIt = CMD_ConvertHexData(buffer, bufLen, mode);
#ifdef nodef
    } else if (*mode == CMDFileMode_Ascii) {
	/* from base-64 encoded */
	rvIt = CMD_ConvertAsciiData(buffer, bufLen);
#endif
    } else {
	/* it's already binary */
	rvIt = NSSItem_Create(NULL, NULL, bufLen, buffer);
    }
    return rvIt;
}

NSSItem *
CMD_GetDataFromFile(PRFileDesc *file, CMDFileMode *mode)
{
    int len;
    unsigned char *inBuf;
    NSSItem *rvIt = NULL;
    inBuf = CMD_ReadFile(file, &len);
    rvIt = CMD_GetDataFromBuffer(inBuf, len, mode);
    free(inBuf);
    return rvIt;
}

NSSItem *
CMD_GetInput(CMDRunTimeData *rtData)
{
    CMDFileData *fData = &rtData->input;
    if (fData->file) {
	return CMD_GetDataFromFile(fData->file, &fData->mode);
    } else if (fData->str) {
	return CMD_GetDataFromBuffer(fData->str, strlen(fData->str), 
	                             &fData->mode);
    } else {
	fprintf(stderr, "No input data specified.\n");
	return NULL;
    }
}

void
CMD_DumpOutput(NSSItem *output, CMDRunTimeData *rtData)
{
    int i;
    unsigned char *outBuf = output->data;
    CMDFileData *fData = &rtData->output;
    switch (fData->mode) {
    case CMDFileMode_Binary:
    case CMDFileMode_PrettyPrint: /* this is the default */
	PR_Write(fData->file, output->data, output->size);
	break;
    case CMDFileMode_Hex:
	for (i=0; i<output->size; i++) {
	    PR_fprintf(fData->file, "%02X", outBuf[i]);
	}
	PR_fprintf(fData->file, "\n");
	break;
    case CMDFileMode_HexWithSpace:
	for (i=0; i<output->size; i++) {
	    PR_fprintf(fData->file, "%02X ", outBuf[i]);
	}
	PR_fprintf(fData->file, "\n");
	break;
    case CMDFileMode_HexConvertedWithSpace:
	for (i=0; i<output->size; i++) {
	    /* using 0x because NSPR chokes on # */
	    PR_fprintf(fData->file, "0x%02X ", outBuf[i]);
	}
	PR_fprintf(fData->file, "\n");
	break;
    case CMDFileMode_Ascii:
	break;
    }
}

