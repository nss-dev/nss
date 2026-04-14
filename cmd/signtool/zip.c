/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "signtool.h"
#include "zip.h"
#include "zlib.h"
#include "prmem.h"

static void inttox(int in, char *out);
static void longtox(long in, char *out);

/****************************************************************
 *
 * J z i p O p e n
 *
 * Opens a new ZIP file and creates a new ZIPfile structure to
 * control the process of installing files into a zip.
 */
ZIPfile *
JzipOpen(char *filename, char *comment)
{
    ZIPfile *zipfile;
    PRExplodedTime prtime;

    zipfile = PORT_ZAlloc(sizeof(ZIPfile));
    if (!zipfile)
        out_of_memory();

    /* Construct time and date */
    MPR_ExplodeTime(MPR_Now(), MPR_LocalTimeParameters, &prtime);
    zipfile->date = ((prtime.tm_year - 1980) << 9) |
                    ((prtime.tm_month + 1) << 5) |
                    prtime.tm_mday;
    zipfile->time = (prtime.tm_hour << 11) |
                    (prtime.tm_min << 5) |
                    (prtime.tm_sec & 0x3f);

    zipfile->fp = NULL;
    if (filename &&
        (zipfile->fp = MPR_Open(filename,
                               PR_WRONLY |
                                   PR_CREATE_FILE |
                                   PR_TRUNCATE,
                               0777)) == NULL) {
        char *nsprErr;
        if (MPR_GetErrorTextLength()) {
            nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
            MPR_GetErrorText(nsprErr);
        } else {
            nsprErr = NULL;
        }
        MPR_fprintf(errorFD, "%s: can't open output jar, %s.%s\n",
                   PROGRAM_NAME,
                   filename, nsprErr ? nsprErr : "");
        if (nsprErr)
            MPR_Free(nsprErr);
        errorCount++;
        exit(ERRX);
    }

    zipfile->list = NULL;
    if (filename) {
        zipfile->filename = PORT_ZAlloc(strlen(filename) + 1);
        if (!zipfile->filename)
            out_of_memory();
        PORT_Strcpy(zipfile->filename, filename);
    }
    if (comment) {
        zipfile->comment = PORT_ZAlloc(strlen(comment) + 1);
        if (!zipfile->comment)
            out_of_memory();
        PORT_Strcpy(zipfile->comment, comment);
    }

    return zipfile;
}

static void *
my_alloc_func(void *opaque, uInt items, uInt size)
{
    return PORT_Alloc(items * size);
}

static void
my_free_func(void *opaque, void *address)
{
    PORT_Free(address);
}

static void
handle_zerror(int err, char *msg)
{
    if (!msg) {
        msg = "";
    }

    errorCount++; /* unless Z_OK...see below */

    switch (err) {
        case Z_OK:
            MPR_fprintf(errorFD, "No error: %s\n", msg);
            errorCount--; /* this was incremented above */
            break;
        case Z_MEM_ERROR:
            MPR_fprintf(errorFD, "Deflation ran out of memory: %s\n", msg);
            break;
        case Z_STREAM_ERROR:
            MPR_fprintf(errorFD, "Invalid compression level: %s\n", msg);
            break;
        case Z_VERSION_ERROR:
            MPR_fprintf(errorFD, "Incompatible compression library version: %s\n",
                       msg);
            break;
        case Z_DATA_ERROR:
            MPR_fprintf(errorFD, "Compression data error: %s\n", msg);
            break;
        default:
            MPR_fprintf(errorFD, "Unknown error in compression library: %s\n", msg);
            break;
    }
}

/****************************************************************
 *
 * J z i p A d d
 *
 * Adds a new file into a ZIP file.  The ZIP file must have already
 * been opened with JzipOpen.
 */
int
JzipAdd(char *fullname, char *filename, ZIPfile *zipfile, int lvl)
{
    ZIPentry *entry;
    PRFileDesc *readfp;
    PRFileDesc *zipfp;
    unsigned long crc;
    unsigned long local_size_pos;
    int num;
    int err;
    int deflate_percent;
    z_stream zstream;
    Bytef inbuf[BUFSIZ];
    Bytef outbuf[BUFSIZ];

    if (!fullname || !filename || !zipfile) {
        return -1;
    }

    zipfp = zipfile->fp;
    if (!zipfp)
        return -1;

    if ((readfp = MPR_Open(fullname, PR_RDONLY, 0777)) == NULL) {
        char *nsprErr;
        if (MPR_GetErrorTextLength()) {
            nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
            MPR_GetErrorText(nsprErr);
        } else {
            nsprErr = NULL;
        }
        MPR_fprintf(errorFD, "%s: %s\n", fullname, nsprErr ? nsprErr : "");
        errorCount++;
        if (nsprErr)
            MPR_Free(nsprErr);
        exit(ERRX);
    }

    /*
     * Make sure the input file is not the output file.
     * Add a few bytes to the end of the JAR file and see if the input file
     * twitches
     */
    {
        PRInt32 endOfJar;
        PRInt32 inputSize;
        PRBool isSame;

        inputSize = MPR_Available(readfp);

        endOfJar = MPR_Seek(zipfp, 0L, PR_SEEK_CUR);

        if (MPR_Write(zipfp, "abcde", 5) < 5) {
            char *nsprErr;

            if (MPR_GetErrorTextLength()) {
                nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
                MPR_GetErrorText(nsprErr);
            } else {
                nsprErr = NULL;
            }
            MPR_fprintf(errorFD, "Writing to zip file: %s\n",
                       nsprErr ? nsprErr : "");
            if (nsprErr)
                MPR_Free(nsprErr);
            errorCount++;
            exit(ERRX);
        }

        isSame = (MPR_Available(readfp) != inputSize);

        MPR_Seek(zipfp, endOfJar, PR_SEEK_SET);

        if (isSame) {
            /* It's the same file! Forget it! */
            MPR_Close(readfp);
            return 0;
        }
    }

    if (verbosity >= 0) {
        MPR_fprintf(outputFD, "adding %s to %s...", fullname, zipfile->filename);
    }

    entry = PORT_ZAlloc(sizeof(ZIPentry));
    if (!entry)
        out_of_memory();

    entry->filename = PORT_Strdup(filename);
    entry->comment = NULL;

    /* Set up local file header */
    longtox(LSIG, entry->local.signature);
    inttox(strlen(filename), entry->local.filename_len);
    inttox(zipfile->time, entry->local.time);
    inttox(zipfile->date, entry->local.date);
    inttox(Z_DEFLATED, entry->local.method);

    /* Set up central directory entry */
    longtox(CSIG, entry->central.signature);
    inttox(strlen(filename), entry->central.filename_len);
    if (entry->comment) {
        inttox(strlen(entry->comment), entry->central.commentfield_len);
    }
    longtox(MPR_Seek(zipfile->fp, 0, PR_SEEK_CUR),
            entry->central.localhdr_offset);
    inttox(zipfile->time, entry->central.time);
    inttox(zipfile->date, entry->central.date);
    inttox(Z_DEFLATED, entry->central.method);

    /* Compute crc.  Too bad we have to process the whole file to do this*/
    crc = crc32(0L, NULL, 0);
    while ((num = MPR_Read(readfp, inbuf, BUFSIZ)) > 0) {
        crc = crc32(crc, inbuf, num);
    }
    MPR_Seek(readfp, 0L, PR_SEEK_SET);

    /* Store CRC */
    longtox(crc, entry->local.crc32);
    longtox(crc, entry->central.crc32);

    /* Stick this entry onto the end of the list */
    entry->next = NULL;
    if (zipfile->list == NULL) {
        /* First entry */
        zipfile->list = entry;
    } else {
        ZIPentry *pe;

        pe = zipfile->list;
        while (pe->next != NULL) {
            pe = pe->next;
        }
        pe->next = entry;
    }

    /*
     * Start writing stuff out
     */

    local_size_pos = MPR_Seek(zipfp, 0, PR_SEEK_CUR) + 18;
    /* File header */
    if (MPR_Write(zipfp, &entry->local, sizeof(struct ZipLocal)) <
        sizeof(struct ZipLocal)) {
        char *nsprErr;
        if (MPR_GetErrorTextLength()) {
            nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
            MPR_GetErrorText(nsprErr);
        } else {
            nsprErr = NULL;
        }
        MPR_fprintf(errorFD, "Writing zip data: %s\n", nsprErr ? nsprErr : "");
        if (nsprErr)
            MPR_Free(nsprErr);
        errorCount++;
        exit(ERRX);
    }

    /* File Name */
    if (MPR_Write(zipfp, filename, strlen(filename)) < strlen(filename)) {
        char *nsprErr;
        if (MPR_GetErrorTextLength()) {
            nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
            MPR_GetErrorText(nsprErr);
        } else {
            nsprErr = NULL;
        }
        MPR_fprintf(errorFD, "Writing zip data: %s\n", nsprErr ? nsprErr : "");
        if (nsprErr)
            MPR_Free(nsprErr);
        errorCount++;
        exit(ERRX);
    }

    /*
     * File data
     */
    /* Initialize zstream */
    zstream.zalloc = my_alloc_func;
    zstream.zfree = my_free_func;
    zstream.opaque = NULL;
    zstream.next_in = inbuf;
    zstream.avail_in = BUFSIZ;
    zstream.next_out = outbuf;
    zstream.avail_out = BUFSIZ;
    /* Setting the windowBits to -MAX_WBITS is an undocumented feature of
     * zlib (see deflate.c in zlib).  It is the same thing that Java does
     * when you specify the nowrap option for deflation in java.util.zip.
     * It causes zlib to leave out its headers and footers, which don't
     * work in PKZIP files.
     */
    err = deflateInit2(&zstream, lvl, Z_DEFLATED,
                       -MAX_WBITS, 8 /*default*/, Z_DEFAULT_STRATEGY);
    if (err != Z_OK) {
        handle_zerror(err, zstream.msg);
        exit(ERRX);
    }

    while ((zstream.avail_in = MPR_Read(readfp, inbuf, BUFSIZ)) > 0) {
        zstream.next_in = inbuf;
        /* Process this chunk of data */
        while (zstream.avail_in > 0) {
            err = deflate(&zstream, Z_NO_FLUSH);
            if (err != Z_OK) {
                handle_zerror(err, zstream.msg);
                exit(ERRX);
            }
            if (zstream.avail_out <= 0) {
                if (MPR_Write(zipfp, outbuf, BUFSIZ) < BUFSIZ) {
                    char *nsprErr;
                    if (MPR_GetErrorTextLength()) {
                        nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
                        MPR_GetErrorText(nsprErr);
                    } else {
                        nsprErr = NULL;
                    }
                    MPR_fprintf(errorFD, "Writing zip data: %s\n",
                               nsprErr ? nsprErr : "");
                    if (nsprErr)
                        MPR_Free(nsprErr);
                    errorCount++;
                    exit(ERRX);
                }
                zstream.next_out = outbuf;
                zstream.avail_out = BUFSIZ;
            }
        }
    }

    /* Now flush everything */
    while (1) {
        err = deflate(&zstream, Z_FINISH);
        if (err == Z_STREAM_END) {
            break;
        } else if (err == Z_OK) {
            /* output buffer full, repeat */
        } else {
            handle_zerror(err, zstream.msg);
            exit(ERRX);
        }
        if (MPR_Write(zipfp, outbuf, BUFSIZ) < BUFSIZ) {
            char *nsprErr;
            if (MPR_GetErrorTextLength()) {
                nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
                MPR_GetErrorText(nsprErr);
            } else {
                nsprErr = NULL;
            }
            MPR_fprintf(errorFD, "Writing zip data: %s\n",
                       nsprErr ? nsprErr : "");
            if (nsprErr)
                MPR_Free(nsprErr);
            errorCount++;
            exit(ERRX);
        }
        zstream.avail_out = BUFSIZ;
        zstream.next_out = outbuf;
    }

    /* If there's any output left, write it out. */
    if (zstream.next_out != outbuf) {
        if (MPR_Write(zipfp, outbuf, zstream.next_out - outbuf) <
            zstream.next_out - outbuf) {
            char *nsprErr;
            if (MPR_GetErrorTextLength()) {
                nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
                MPR_GetErrorText(nsprErr);
            } else {
                nsprErr = NULL;
            }
            MPR_fprintf(errorFD, "Writing zip data: %s\n",
                       nsprErr ? nsprErr : "");
            if (nsprErr)
                MPR_Free(nsprErr);
            errorCount++;
            exit(ERRX);
        }
        zstream.avail_out = BUFSIZ;
        zstream.next_out = outbuf;
    }

    /* Now that we know the compressed size, write this to the headers */
    longtox(zstream.total_in, entry->local.orglen);
    longtox(zstream.total_out, entry->local.size);
    if (MPR_Seek(zipfp, local_size_pos, PR_SEEK_SET) == -1) {
        char *nsprErr;
        if (MPR_GetErrorTextLength()) {
            nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
            MPR_GetErrorText(nsprErr);
        } else {
            nsprErr = NULL;
        }
        MPR_fprintf(errorFD, "Accessing zip file: %s\n", nsprErr ? nsprErr : "");
        if (nsprErr)
            MPR_Free(nsprErr);
        errorCount++;
        exit(ERRX);
    }
    if (MPR_Write(zipfp, entry->local.size, 8) != 8) {
        char *nsprErr;
        if (MPR_GetErrorTextLength()) {
            nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
            MPR_GetErrorText(nsprErr);
        } else {
            nsprErr = NULL;
        }
        MPR_fprintf(errorFD, "Writing zip data: %s\n", nsprErr ? nsprErr : "");
        if (nsprErr)
            MPR_Free(nsprErr);
        errorCount++;
        exit(ERRX);
    }
    if (MPR_Seek(zipfp, 0L, PR_SEEK_END) == -1) {
        char *nsprErr;
        if (MPR_GetErrorTextLength()) {
            nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
            MPR_GetErrorText(nsprErr);
        } else {
            nsprErr = NULL;
        }
        MPR_fprintf(errorFD, "Accessing zip file: %s\n",
                   nsprErr ? nsprErr : "");
        if (nsprErr)
            MPR_Free(nsprErr);
        errorCount++;
        exit(ERRX);
    }
    longtox(zstream.total_in, entry->central.orglen);
    longtox(zstream.total_out, entry->central.size);

    /* Close out the deflation operation */
    err = deflateEnd(&zstream);
    if (err != Z_OK) {
        handle_zerror(err, zstream.msg);
        exit(ERRX);
    }

    MPR_Close(readfp);

    if ((zstream.total_in > zstream.total_out) && (zstream.total_in > 0)) {
        deflate_percent = (int)((zstream.total_in -
                                 zstream.total_out) *
                                100 / zstream.total_in);
    } else {
        deflate_percent = 0;
    }
    if (verbosity >= 0) {
        MPR_fprintf(outputFD, "(deflated %d%%)\n", deflate_percent);
    }

    return 0;
}

/********************************************************************
 * J z i p C l o s e
 *
 * Finishes the ZipFile. ALSO DELETES THE ZIPFILE STRUCTURE PASSED IN!!
 */
int
JzipClose(ZIPfile *zipfile)
{
    ZIPentry *pe, *dead;
    PRFileDesc *zipfp;
    struct ZipEnd zipend;
    unsigned int entrycount = 0;

    if (!zipfile) {
        return -1;
    }

    if (!zipfile->filename) {
        /* bogus */
        return 0;
    }

    zipfp = zipfile->fp;
    zipfile->central_start = MPR_Seek(zipfp, 0L, PR_SEEK_CUR);

    /* Write out all the central directories */
    pe = zipfile->list;
    while (pe) {
        entrycount++;

        /* Write central directory info */
        if (MPR_Write(zipfp, &pe->central, sizeof(struct ZipCentral)) <
            sizeof(struct ZipCentral)) {
            char *nsprErr;
            if (MPR_GetErrorTextLength()) {
                nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
                MPR_GetErrorText(nsprErr);
            } else {
                nsprErr = NULL;
            }
            MPR_fprintf(errorFD, "Writing zip data: %s\n",
                       nsprErr ? nsprErr : "");
            if (nsprErr)
                MPR_Free(nsprErr);
            errorCount++;
            exit(ERRX);
        }

        /* Write filename */
        if (MPR_Write(zipfp, pe->filename, strlen(pe->filename)) <
            strlen(pe->filename)) {
            char *nsprErr;
            if (MPR_GetErrorTextLength()) {
                nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
                MPR_GetErrorText(nsprErr);
            } else {
                nsprErr = NULL;
            }
            MPR_fprintf(errorFD, "Writing zip data: %s\n",
                       nsprErr ? nsprErr : "");
            if (nsprErr)
                MPR_Free(nsprErr);
            errorCount++;
            exit(ERRX);
        }

        /* Write file comment */
        if (pe->comment) {
            if (MPR_Write(zipfp, pe->comment, strlen(pe->comment)) <
                strlen(pe->comment)) {
                char *nsprErr;
                if (MPR_GetErrorTextLength()) {
                    nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
                    MPR_GetErrorText(nsprErr);
                } else {
                    nsprErr = NULL;
                }
                MPR_fprintf(errorFD, "Writing zip data: %s\n",
                           nsprErr ? nsprErr : "");
                if (nsprErr)
                    MPR_Free(nsprErr);
                errorCount++;
                exit(ERRX);
            }
        }

        /* Delete the structure */
        dead = pe;
        pe = pe->next;
        if (dead->filename) {
            PORT_Free(dead->filename);
        }
        if (dead->comment) {
            PORT_Free(dead->comment);
        }
        PORT_Free(dead);
    }
    zipfile->central_end = MPR_Seek(zipfile->fp, 0L, PR_SEEK_CUR);

    /* Create the ZipEnd structure */
    PORT_Memset(&zipend, 0, sizeof(zipend));
    longtox(ESIG, zipend.signature);
    inttox(entrycount, zipend.total_entries_disk);
    inttox(entrycount, zipend.total_entries_archive);
    longtox(zipfile->central_end - zipfile->central_start,
            zipend.central_dir_size);
    longtox(zipfile->central_start, zipend.offset_central_dir);
    if (zipfile->comment) {
        inttox(strlen(zipfile->comment), zipend.commentfield_len);
    }

    /* Write out ZipEnd xtructure */
    if (MPR_Write(zipfp, &zipend, sizeof(zipend)) < sizeof(zipend)) {
        char *nsprErr;
        if (MPR_GetErrorTextLength()) {
            nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
            MPR_GetErrorText(nsprErr);
        } else {
            nsprErr = NULL;
        }
        MPR_fprintf(errorFD, "Writing zip data: %s\n",
                   nsprErr ? nsprErr : "");
        if (nsprErr)
            MPR_Free(nsprErr);
        errorCount++;
        exit(ERRX);
    }

    /* Write out Zipfile comment */
    if (zipfile->comment) {
        if (MPR_Write(zipfp, zipfile->comment, strlen(zipfile->comment)) <
            strlen(zipfile->comment)) {
            char *nsprErr;
            if (MPR_GetErrorTextLength()) {
                nsprErr = MPR_Malloc(MPR_GetErrorTextLength() + 1);
                MPR_GetErrorText(nsprErr);
            } else {
                nsprErr = NULL;
            }
            MPR_fprintf(errorFD, "Writing zip data: %s\n",
                       nsprErr ? nsprErr : "");
            if (nsprErr)
                MPR_Free(nsprErr);
            errorCount++;
            exit(ERRX);
        }
    }

    MPR_Close(zipfp);

    /* Free the memory of the zipfile structure */
    if (zipfile->filename) {
        PORT_Free(zipfile->filename);
    }
    if (zipfile->comment) {
        PORT_Free(zipfile->comment);
    }
    PORT_Free(zipfile);

    return 0;
}

/**********************************************
 *  i n t t o x
 *
 *  Converts a two byte ugly endianed integer
 *  to our platform's integer.
 *
 */

static void
inttox(int in, char *out)
{
    out[0] = (in & 0xFF);
    out[1] = (in & 0xFF00) >> 8;
}

/*********************************************
 *  l o n g t o x
 *
 *  Converts a four byte ugly endianed integer
 *  to our platform's integer.
 *
 */

static void
longtox(long in, char *out)
{
    out[0] = (in & 0xFF);
    out[1] = (in & 0xFF00) >> 8;
    out[2] = (in & 0xFF0000) >> 16;
    out[3] = (in & 0xFF000000) >> 24;
}
