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

#ifndef BASE_H
#define BASE_H

#ifdef DEBUG
static const char BASE_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

/*
 * base.h
 *
 * This header file contains basic prototypes and preprocessor 
 * definitions used throughout nss but not available publicly.
 */

#ifndef BASET_H
#include "baset.h"
#endif /* BASET_H */

#ifndef NSSBASE_H
#include "nssbase.h"
#endif /* NSSBASE_H */

#include "plhash.h"
#include "prthread.h"

PR_BEGIN_EXTERN_C

#define nss_ASSERT PR_ASSERT

/*
 * NSSArena
 *
 * The nonpublic methods relating to this type are:
 *
 *  nssArena_Create  -- constructor
 *  nssArena_Destroy
 *  nssArena_Mark
 *  nssArena_Release
 *  nssArena_Unmark
 *
 *  nss_ZAlloc
 *  nss_ZFreeIf
 *  nss_ZRealloc
 *
 * Additionally, there are some preprocessor macros:
 *
 *  nss_ZNEW
 *  nss_ZNEWARRAY
 *
 * The following preprocessor macro is also always available:
 *
 *  nssArena_VERIFYPOINTER
 *
 * A constant PLHashAllocOps structure is available for users
 * of the NSPL PLHashTable routines.
 *
 *  nssArenaHashAllocOps
 */

/*
 * nssArena_Create
 *
 * This routine creates a new memory arena.  This routine may return
 * NULL upon error, in which case it will have set an error on the 
 * error stack.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  NULL upon error
 *  A pointer to an NSSArena upon success
 */

/*
 * XXX fgmr
 * Arenas can be named upon creation; this is mostly of use when
 * debugging.  Should we expose that here, allowing an optional
 * "const char *name" argument?  Should the public version of this
 * call (NSSArena_Create) have it too?
 */

NSS_EXTERN NSSArena *
nssArena_Create
(
  void
);

/*
 * nssArena_Destroy
 *
 * This routine will destroy the specified arena, freeing all memory
 * allocated from it.  This routine returns a PRStatus value; if 
 * successful, it will return PR_SUCCESS.  If unsuccessful, it will
 * set an error on the error stack and return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  PR_SUCCESS
 *  PR_FAILURE
 */

NSS_EXTERN PRStatus
nssArena_Destroy
(
  NSSArena *arena
);

/*
 * nssArena_Mark
 *
 * This routine "marks" the current state of an arena.  Space
 * allocated after the arena has been marked can be freed by
 * releasing the arena back to the mark with nssArena_Release,
 * or committed by calling nssArena_Unmark.  When successful, 
 * this routine returns a valid nssArenaMark pointer.  This 
 * routine may return NULL upon error, in which case it will 
 * have set an error on the error stack.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_ARENA_MARKED_BY_ANOTHER_THREAD
 *
 * Return value:
 *  NULL upon failure
 *  An nssArenaMark pointer upon success
 */

NSS_EXTERN nssArenaMark *
nssArena_Mark
(
  NSSArena *arena
);

/*
 * nssArena_Release
 *
 * This routine invalidates and releases all memory allocated from
 * the specified arena after the point at which the specified mark
 * was obtained.  This routine returns a PRStatus value; if successful,
 * it will return PR_SUCCESS.  If unsuccessful, it will set an error
 * on the error stack and return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_ARENA_MARK
 *  NSS_ERROR_ARENA_MARKED_BY_ANOTHER_THREAD
 *
 * Return value:
 *  PR_SUCCESS
 *  PR_FAILURE
 */

NSS_EXTERN PRStatus
nssArena_Release
(
  NSSArena *arena,
  nssArenaMark *arenaMark
);

/*
 * nssArena_Unmark
 *
 * This routine "commits" the indicated mark and any marks after
 * it, making them unreleasable.  Note that any earlier marks can
 * still be released, and such a release will invalidate these
 * later unmarked regions.  If an arena is to be safely shared by
 * more than one thread, all marks must be either released or
 * unmarked.  This routine returns a PRStatus value; if successful,
 * it will return PR_SUCCESS.  If unsuccessful, it will set an error
 * on the error stack and return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_ARENA_MARK
 *  NSS_ERROR_ARENA_MARKED_BY_ANOTHER_THREAD
 *
 * Return value:
 *  PR_SUCCESS
 *  PR_FAILURE
 */

NSS_EXTERN PRStatus
nssArena_Unmark
(
  NSSArena *arena,
  nssArenaMark *arenaMark
);

#ifdef ARENA_DESTRUCTOR_LIST

/*
 * nssArena_registerDestructor
 *
 * This routine stores a pointer to a callback and an arbitrary
 * pointer-sized argument in the arena, at the current point in
 * the mark stack.  If the arena is destroyed, or an "earlier"
 * mark is released, then this destructor will be called at that
 * time.  Note that the destructor will be called with the arena
 * locked, which means the destructor may free memory in that
 * arena, but it may not allocate or cause to be allocated any
 * memory.  This callback facility was included to support our
 * debug-version pointer-tracker feature; overuse runs counter to
 * the the original intent of arenas.  This routine returns a 
 * PRStatus value; if successful, it will return PR_SUCCESS.  If 
 * unsuccessful, it will set an error on the error stack and 
 * return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  PR_SUCCESS
 *  PR_FAILURE
 */

NSS_EXTERN PRStatus
nssArena_registerDestructor
(
  NSSArena *arena,
  void (*destructor)(void *argument),
  void *arg
);

/*
 * nssArena_deregisterDestructor
 *
 * This routine will remove the first destructor in the specified
 * arena which has the specified destructor and argument values.
 * The destructor will not be called.  This routine returns a
 * PRStatus value; if successful, it will return PR_SUCCESS.  If 
 * unsuccessful, it will set an error on the error stack and 
 * return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NOT_FOUND
 *
 * Return value:
 *  PR_SUCCESS
 *  PR_FAILURE
 */

NSS_EXTERN PRStatus
nssArena_deregisterDestructor
(
  NSSArena *arena,
  void (*destructor)(void *argument),
  void *arg
);

#endif /* ARENA_DESTRUCTOR_LIST */

/*
 * nss_ZAlloc
 *
 * This routine allocates and zeroes a section of memory of the 
 * size, and returns to the caller a pointer to that memory.  If
 * the optional arena argument is non-null, the memory will be
 * obtained from that arena; otherwise, the memory will be obtained
 * from the heap.  This routine may return NULL upon error, in
 * which case it will have set an error upon the error stack.  The
 * value specified for size may be zero; in which case a valid 
 * zero-length block of memory will be allocated.  This block may
 * be expanded by calling nss_ZRealloc.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_ARENA_MARKED_BY_ANOTHER_THREAD
 *
 * Return value:
 *  NULL upon error
 *  A pointer to the new segment of zeroed memory
 */

NSS_EXTERN void *
nss_ZAlloc
(
  NSSArena *arenaOpt,
  PRUint32 size
);

/*
 * nss_ZFreeIf
 *
 * If the specified pointer is non-null, then the region of memory 
 * to which it points -- which must have been allocated with 
 * nss_ZAlloc -- will be zeroed and released.  This routine 
 * returns a PRStatus value; if successful, it will return PR_SUCCESS.
 * If unsuccessful, it will set an error on the error stack and return 
 * PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_POINTER
 *
 * Return value:
 *  PR_SUCCESS
 *  PR_FAILURE
 */

NSS_EXTERN PRStatus
nss_ZFreeIf
(
  void *pointer
);

/*
 * nss_ZRealloc
 *
 * This routine reallocates a block of memory obtained by calling
 * nss_ZAlloc or nss_ZRealloc.  The portion of memory 
 * between the new and old sizes -- which is either being newly
 * obtained or released -- is in either case zeroed.  This routine 
 * may return NULL upon failure, in which case it will have placed 
 * an error on the error stack.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_POINTER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_ARENA_MARKED_BY_ANOTHER_THREAD
 *
 * Return value:
 *  NULL upon error
 *  A pointer to the replacement segment of memory
 */

NSS_EXTERN void *
nss_ZRealloc
(
  void *pointer,
  PRUint32 newSize
);

/*
 * nss_ZNEW
 *
 * This preprocessor macro will allocate memory for a new object
 * of the specified type with nss_ZAlloc, and will cast the
 * return value appropriately.  If the optional arena argument is 
 * non-null, the memory will be obtained from that arena; otherwise, 
 * the memory will be obtained from the heap.  This routine may 
 * return NULL upon error, in which case it will have set an error 
 * upon the error stack.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  NULL upon error
 *  A pointer to the new segment of zeroed memory
 */

/* The following line exceeds 72 characters, but emacs screws up if I split it. */
#define nss_ZNEW(arenaOpt, type) ((type *)nss_ZAlloc((arenaOpt), sizeof(type)))

/*
 * nss_ZNEWARRAY
 *
 * This preprocessor macro will allocate memory for an array of
 * new objects, and will cast the return value appropriately.
 * If the optional arena argument is non-null, the memory will 
 * be obtained from that arena; otherwise, the memory will be 
 * obtained from the heap.  This routine may return NULL upon 
 * error, in which case it will have set an error upon the error 
 * stack.  The array size may be specified as zero.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  NULL upon error
 *  A pointer to the new segment of zeroed memory
 */

/* The following line exceeds 72 characters, but emacs screws up if I split it. */
#define nss_ZNEWARRAY(arenaOpt, type, quantity) ((type *)nss_ZAlloc((arenaOpt), sizeof(type) * (quantity)))

/*
 * nss_ZREALLOCARRAY
 *
 * This preprocessor macro will reallocate memory for an array of
 * new objects, and will cast the return value appropriately.
 * This routine may return NULL upon error, in which case it will 
 *  have set an error upon the error stack.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_POINTER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_ARENA_MARKED_BY_ANOTHER_THREAD
 *
 * Return value:
 *  NULL upon error
 *  A pointer to the replacement segment of memory
 */
#define nss_ZREALLOCARRAY(p, type, quantity) ((type *)nss_ZRealloc((p), sizeof(type) * (quantity)))

/*
 * nssArenaHashAllocOps
 *
 * This constant structure contains allocation callbacks designed for
 * use with the NSPL routine PL_NewHashTable.  For example:
 *
 *  NSSArena *hashTableArena = nssArena_Create();
 *  PLHashTable *t = PL_NewHashTable(n, hasher, key_compare, 
 *    value_compare, nssArenaHashAllocOps, hashTableArena);
 */

NSS_EXTERN_DATA PLHashAllocOps nssArenaHashAllocOps;

/*
 * The error stack
 *
 * The nonpublic methods relating to the error stack are:
 *
 *  nss_SetError
 *  nss_ClearErrorStack
 */

/*
 * nss_SetError
 *
 * This routine places a new error code on the top of the calling 
 * thread's error stack.  Calling this routine wiht an error code
 * of zero will clear the error stack.
 */

NSS_EXTERN void
nss_SetError
(
  PRUint32 error
);

/*
 * nss_ClearErrorStack
 *
 * This routine clears the calling thread's error stack.
 */

NSS_EXTERN void
nss_ClearErrorStack
(
  void
);

/*
 * NSSItem
 *
 * nssItem_Create
 * nssItem_Duplicate
 * nssItem_Equal
 */

NSS_EXTERN NSSItem *
nssItem_Create
(
  NSSArena *arenaOpt,
  NSSItem *rvOpt,
  PRUint32 length,
  const void *data
);

NSS_EXTERN void
nssItem_Destroy
(
  NSSItem *item
);

NSS_EXTERN NSSItem *
nssItem_Duplicate
(
  NSSItem *obj,
  NSSArena *arenaOpt,
  NSSItem *rvOpt
);

NSS_EXTERN PRBool
nssItem_Equal
(
  const NSSItem *one,
  const NSSItem *two,
  PRStatus *statusOpt
);

/*
 * NSSUTF8
 *
 *  nssUTF8_CaseIgnoreMatch
 *  nssUTF8_Duplicate
 *  nssUTF8_Size
 *  nssUTF8_Length
 *  nssUTF8_CopyIntoFixedBuffer
 */

/*
 * nssUTF8_CaseIgnoreMatch
 * 
 * Returns true if the two UTF8-encoded strings pointed to by the 
 * two specified NSSUTF8 pointers differ only in typcase.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_POINTER
 *
 * Return value:
 *  PR_TRUE if the strings match, ignoring case
 *  PR_FALSE if they don't
 *  PR_FALSE upon error
 */

NSS_EXTERN PRBool
nssUTF8_CaseIgnoreMatch
(
  const NSSUTF8 *a,
  const NSSUTF8 *b,
  PRStatus *statusOpt
);

/*
 * nssUTF8_Duplicate
 *
 * This routine duplicates the UTF8-encoded string pointed to by the
 * specified NSSUTF8 pointer.  If the optional arenaOpt argument is
 * not null, the memory required will be obtained from that arena;
 * otherwise, the memory required will be obtained from the heap.
 * A pointer to the new string will be returned.  In case of error,
 * an error will be placed on the error stack and NULL will be 
 * returned.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_POINTER
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 */

NSS_EXTERN NSSUTF8 *
nssUTF8_Duplicate
(
  const NSSUTF8 *s,
  NSSArena *arenaOpt
);

/*
 * nssUTF8_PrintableMatch
 *
 * Returns true if the two Printable strings pointed to by the 
 * two specified NSSUTF8 pointers match when compared with the 
 * rules for Printable String (leading and trailing spaces are 
 * disregarded, extents of whitespace match irregardless of length, 
 * and case is not significant), then PR_TRUE will be returned.
 * Otherwise, PR_FALSE will be returned.  Upon failure, PR_FALSE
 * will be returned.  If the optional statusOpt argument is not
 * NULL, then PR_SUCCESS or PR_FAILURE will be stored in that
 * location.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_POINTER
 *
 * Return value:
 *  PR_TRUE if the strings match, ignoring case
 *  PR_FALSE if they don't
 *  PR_FALSE upon error
 */

NSS_EXTERN PRBool
nssUTF8_PrintableMatch
(
  const NSSUTF8 *a,
  const NSSUTF8 *b,
  PRStatus *statusOpt
);

/*
 * nssUTF8_Size
 *
 * This routine returns the length in bytes (including the terminating
 * null) of the UTF8-encoded string pointed to by the specified
 * NSSUTF8 pointer.  Zero is returned on error.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_POINTER
 *  NSS_ERROR_VALUE_TOO_LARGE
 *
 * Return value:
 *  nonzero size of the string
 *  0 on error
 */

NSS_EXTERN PRUint32
nssUTF8_Size
(
  const NSSUTF8 *s,
  PRStatus *statusOpt
);

/*
 * nssUTF8_Length
 *
 * This routine returns the length in characters (not including the
 * terminating null) of the UTF8-encoded string pointed to by the
 * specified NSSUTF8 pointer.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_POINTER
 *  NSS_ERROR_VALUE_TOO_LARGE
 *  NSS_ERROR_INVALID_STRING
 *
 * Return value:
 *  length of the string (which may be zero)
 *  0 on error
 */

NSS_EXTERN PRUint32
nssUTF8_Length
(
  const NSSUTF8 *s,
  PRStatus *statusOpt
);

/*
 * nssUTF8_Create
 *
 * This routine creates a UTF8 string from a string in some other
 * format.  Some types of string may include embedded null characters,
 * so for them the length parameter must be used.  For string types
 * that are null-terminated, the length parameter is optional; if it
 * is zero, it will be ignored.  If the optional arena argument is
 * non-null, the memory used for the new string will be obtained from
 * that arena, otherwise it will be obtained from the heap.  This
 * routine may return NULL upon error, in which case it will have
 * placed an error on the error stack.
 *
 * The error may be one of the following:
 *  NSS_ERROR_INVALID_POINTER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_UNSUPPORTED_TYPE
 *
 * Return value:
 *  NULL upon error
 *  A non-null pointer to a new UTF8 string otherwise
 */

NSS_EXTERN NSSUTF8 *
nssUTF8_Create
(
  NSSArena *arenaOpt,
  nssStringType type,
  const void *inputString,
  PRUint32 size /* in bytes, not characters */
);

NSS_EXTERN NSSItem *
nssUTF8_GetEncoding
(
  NSSArena *arenaOpt,
  NSSItem *rvOpt,
  nssStringType type,
  NSSUTF8 *string
);

/*
 * nssUTF8_CopyIntoFixedBuffer
 *
 * This will copy a UTF8 string into a fixed-length buffer, making 
 * sure that the all characters are valid.  Any remaining space will
 * be padded with the specified ASCII character, typically either 
 * null or space.
 *
 * Blah, blah, blah.
 */

NSS_EXTERN PRStatus
nssUTF8_CopyIntoFixedBuffer
(
  NSSUTF8 *string,
  char *buffer,
  PRUint32 bufferSize,
  char pad
);

/*
 * nssUTF8_Equal
 *
 */

NSS_EXTERN PRBool
nssUTF8_Equal
(
  const NSSUTF8 *a,
  const NSSUTF8 *b,
  PRStatus *statusOpt
);

/*
 * nssHash
 *
 *  nssHash_Create
 *  nssHash_Destroy
 *  nssHash_Add
 *  nssHash_Remove
 *  nssHash_Count
 *  nssHash_Exists
 *  nssHash_Lookup
 *  nssHash_Iterate
 */

/*
 * nssHash_Create
 *
 */

NSS_EXTERN nssHash *
nssHash_Create
(
  NSSArena *arenaOpt,
  PRUint32 numBuckets,
  PLHashFunction keyHash,
  PLHashComparator keyCompare,
  PLHashComparator valueCompare
);

NSS_EXTERN nssHash *
nssHash_CreatePointer
(
  NSSArena *arenaOpt,
  PRUint32 numBuckets
);

NSS_EXTERN nssHash *
nssHash_CreateString
(
  NSSArena *arenaOpt,
  PRUint32 numBuckets
);

NSS_EXTERN nssHash *
nssHash_CreateItem
(
  NSSArena *arenaOpt,
  PRUint32 numBuckets
);

/*
 * nssHash_Destroy
 *
 */
NSS_EXTERN void
nssHash_Destroy
(
  nssHash *hash
);

/*
 * nssHash_Add
 *
 */

NSS_EXTERN PRStatus
nssHash_Add
(
  nssHash *hash,
  const void *key,
  const void *value
);

/*
 * nssHash_Remove
 *
 */
NSS_EXTERN void
nssHash_Remove
(
  nssHash *hash,
  const void *it
);

/*
 * nssHash_Count
 *
 */
NSS_EXTERN PRUint32
nssHash_Count
(
  nssHash *hash
);

/*
 * nssHash_Exists
 *
 */
NSS_EXTERN PRBool
nssHash_Exists
(
  nssHash *hash,
  const void *it
);

/*
 * nssHash_Lookup
 *
 */
NSS_EXTERN void *
nssHash_Lookup
(
  nssHash *hash,
  const void *it
);

/*
 * nssHash_Iterate
 *
 */
NSS_EXTERN void
nssHash_Iterate
(
  nssHash *hash,
  nssHashIterator fcn,
  void *closure
);

/*
 * libc
 *
 * nsslibc_memcpy
 * nsslibc_memset
 * nsslibc_offsetof
 */

/*
 * nsslibc_memcpy
 *
 * Errors:
 *  NSS_ERROR_INVALID_POINTER
 *
 * Return value:
 *  NULL on error
 *  The destination pointer on success
 */

NSS_EXTERN void *
nsslibc_memcpy
(
  void *dest,
  const void *source,
  PRUint32 n
);

/*
 * nsslibc_memset
 *
 * Errors:
 *  NSS_ERROR_INVALID_POINTER
 *
 * Return value:
 *  NULL on error
 *  The destination pointer on success
 */

NSS_EXTERN void *
nsslibc_memset
(
  void *dest,
  PRUint8 byte,
  PRUint32 n
);

/*
 * nsslibc_memequal
 *
 * Errors:
 *  NSS_ERROR_INVALID_POINTER
 *
 * Return value:
 *  PR_TRUE if they match
 *  PR_FALSE if they don't
 *  PR_FALSE upon error
 */

NSS_EXTERN PRBool
nsslibc_memequal
(
  const void *a,
  const void *b,
  PRUint32 len,
  PRStatus *statusOpt
);

#define nsslibc_offsetof(str, memb) ((PRPtrdiff)(&(((str *)0)->memb)))

/*
 * nss_NewThreadPrivateIndex
 * 
 */

NSS_EXTERN PRStatus
nss_NewThreadPrivateIndex
(
  PRUintn *ip,
  PRThreadPrivateDTOR dtor
);

/*
 * nss_GetThreadPrivate
 *
 */

NSS_EXTERN void *
nss_GetThreadPrivate
(
  PRUintn i
);

/*
 * nss_SetThreadPrivate
 *
 */

NSS_EXTERN void
nss_SetThreadPrivate
(
  PRUintn i,
  void *v
);

PR_END_EXTERN_C

#endif /* BASE_H */
