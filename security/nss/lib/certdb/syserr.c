/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * This file essentially replicates NSPR's source for the functions that
 * map system-specific error codes to NSPR error codes.  We would use 
 * NSPR's functions, instead of duplicating them, but they're private.
 * As long as SSL's server session cache code must do platform native I/O
 * to accomplish its job, and NSPR's error mapping functions remain private,
 * this code will continue to need to be replicated.
 * 
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
 *
 * $Id$
 */

#include "prerror.h"
#include "prlog.h"
#include <errno.h>
 
/* mapping of system -> NSPR error codes, taken from libssl.
 * used when dbm return value < 0, indicating system error.
 */

#if defined(WIN32)

#include <windows.h>

void nss_MD_map_system_error()
{
    PRErrorCode prError;
    PRInt32 err = GetLastError();

    switch (err) {
    case EACCES: 		prError = PR_NO_ACCESS_RIGHTS_ERROR; break;
    case ENOENT: 		prError = PR_FILE_NOT_FOUND_ERROR; break;
    case ERROR_ACCESS_DENIED: 	prError = PR_NO_ACCESS_RIGHTS_ERROR; break;
    case ERROR_ALREADY_EXISTS: 	prError = PR_FILE_EXISTS_ERROR; break;
    case ERROR_DISK_CORRUPT: 	prError = PR_IO_ERROR; break;
    case ERROR_DISK_FULL: 	prError = PR_NO_DEVICE_SPACE_ERROR; break;
    case ERROR_DISK_OPERATION_FAILED: prError = PR_IO_ERROR; break;
    case ERROR_DRIVE_LOCKED: 	prError = PR_FILE_IS_LOCKED_ERROR; break;
    case ERROR_FILENAME_EXCED_RANGE: prError = PR_NAME_TOO_LONG_ERROR; break;
    case ERROR_FILE_CORRUPT: 	prError = PR_IO_ERROR; break;
    case ERROR_FILE_EXISTS: 	prError = PR_FILE_EXISTS_ERROR; break;
    case ERROR_FILE_INVALID: 	prError = PR_BAD_DESCRIPTOR_ERROR; break;
#if ERROR_FILE_NOT_FOUND != ENOENT
    case ERROR_FILE_NOT_FOUND: 	prError = PR_FILE_NOT_FOUND_ERROR; break;
#endif
    case ERROR_HANDLE_DISK_FULL: prError = PR_NO_DEVICE_SPACE_ERROR; break;
    case ERROR_INVALID_ADDRESS: prError = PR_ACCESS_FAULT_ERROR; break;
    case ERROR_INVALID_HANDLE: 	prError = PR_BAD_DESCRIPTOR_ERROR; break;
    case ERROR_INVALID_NAME: 	prError = PR_INVALID_ARGUMENT_ERROR; break;
    case ERROR_INVALID_PARAMETER: prError = PR_INVALID_ARGUMENT_ERROR; break;
    case ERROR_INVALID_USER_BUFFER: prError = PR_INSUFFICIENT_RESOURCES_ERROR; break;
    case ERROR_LOCKED:	 	prError = PR_FILE_IS_LOCKED_ERROR; break;
    case ERROR_NETNAME_DELETED: prError = PR_CONNECT_RESET_ERROR; break;
    case ERROR_NOACCESS: 	prError = PR_ACCESS_FAULT_ERROR; break;
    case ERROR_NOT_ENOUGH_MEMORY: prError = PR_INSUFFICIENT_RESOURCES_ERROR; break;
    case ERROR_NOT_ENOUGH_QUOTA: prError = PR_OUT_OF_MEMORY_ERROR; break;
    case ERROR_NOT_READY: 	prError = PR_IO_ERROR; break;
    case ERROR_NO_MORE_FILES: 	prError = PR_NO_MORE_FILES_ERROR; break;
    case ERROR_OPEN_FAILED: 	prError = PR_IO_ERROR; break;
    case ERROR_OPEN_FILES: 	prError = PR_IO_ERROR; break;
    case ERROR_OUTOFMEMORY: 	prError = PR_INSUFFICIENT_RESOURCES_ERROR; break;
    case ERROR_PATH_BUSY: 	prError = PR_IO_ERROR; break;
    case ERROR_PATH_NOT_FOUND: 	prError = PR_FILE_NOT_FOUND_ERROR; break;
    case ERROR_SEEK_ON_DEVICE: 	prError = PR_IO_ERROR; break;
    case ERROR_SHARING_VIOLATION: prError = PR_FILE_IS_BUSY_ERROR; break;
    case ERROR_STACK_OVERFLOW: 	prError = PR_ACCESS_FAULT_ERROR; break;
    case ERROR_TOO_MANY_OPEN_FILES: prError = PR_SYS_DESC_TABLE_FULL_ERROR; break;
    case ERROR_WRITE_PROTECT: 	prError = PR_NO_ACCESS_RIGHTS_ERROR; break;
    case WSAEACCES: 		prError = PR_NO_ACCESS_RIGHTS_ERROR; break;
    case WSAEADDRINUSE: 	prError = PR_ADDRESS_IN_USE_ERROR; break;
    case WSAEADDRNOTAVAIL: 	prError = PR_ADDRESS_NOT_AVAILABLE_ERROR; break;
    case WSAEAFNOSUPPORT: 	prError = PR_ADDRESS_NOT_SUPPORTED_ERROR; break;
    case WSAEALREADY: 		prError = PR_ALREADY_INITIATED_ERROR; break;
    case WSAEBADF: 		prError = PR_BAD_DESCRIPTOR_ERROR; break;
    case WSAECONNABORTED: 	prError = PR_CONNECT_ABORTED_ERROR; break;
    case WSAECONNREFUSED: 	prError = PR_CONNECT_REFUSED_ERROR; break;
    case WSAECONNRESET: 	prError = PR_CONNECT_RESET_ERROR; break;
    case WSAEDESTADDRREQ: 	prError = PR_INVALID_ARGUMENT_ERROR; break;
    case WSAEFAULT: 		prError = PR_ACCESS_FAULT_ERROR; break;
    case WSAEHOSTUNREACH: 	prError = PR_HOST_UNREACHABLE_ERROR; break;
    case WSAEINVAL: 		prError = PR_INVALID_ARGUMENT_ERROR; break;
    case WSAEISCONN: 		prError = PR_IS_CONNECTED_ERROR; break;
    case WSAEMFILE: 		prError = PR_PROC_DESC_TABLE_FULL_ERROR; break;
    case WSAEMSGSIZE: 		prError = PR_BUFFER_OVERFLOW_ERROR; break;
    case WSAENETDOWN: 		prError = PR_NETWORK_DOWN_ERROR; break;
    case WSAENETRESET: 		prError = PR_CONNECT_ABORTED_ERROR; break;
    case WSAENETUNREACH: 	prError = PR_NETWORK_UNREACHABLE_ERROR; break;
    case WSAENOBUFS: 		prError = PR_INSUFFICIENT_RESOURCES_ERROR; break;
    case WSAENOPROTOOPT: 	prError = PR_INVALID_ARGUMENT_ERROR; break;
    case WSAENOTCONN: 		prError = PR_NOT_CONNECTED_ERROR; break;
    case WSAENOTSOCK: 		prError = PR_NOT_SOCKET_ERROR; break;
    case WSAEOPNOTSUPP: 	prError = PR_OPERATION_NOT_SUPPORTED_ERROR; break;
    case WSAEPROTONOSUPPORT: 	prError = PR_PROTOCOL_NOT_SUPPORTED_ERROR; break;
    case WSAEPROTOTYPE: 	prError = PR_INVALID_ARGUMENT_ERROR; break;
    case WSAESHUTDOWN: 		prError = PR_SOCKET_SHUTDOWN_ERROR; break;
    case WSAESOCKTNOSUPPORT: 	prError = PR_INVALID_ARGUMENT_ERROR; break;
    case WSAETIMEDOUT: 		prError = PR_CONNECT_ABORTED_ERROR; break;
    case WSAEWOULDBLOCK: 	prError = PR_WOULD_BLOCK_ERROR; break;
    default: 			prError = PR_UNKNOWN_ERROR; break;
    }
    PR_SetError(prError, err);
}

#elif defined(XP_UNIX)

void nss_MD_map_system_error()
{
    PRErrorCode prError;
    int err = errno;

    switch (err ) {
    case EACCES:	prError = PR_NO_ACCESS_RIGHTS_ERROR; break;
    case EADDRINUSE:	prError = PR_ADDRESS_IN_USE_ERROR; break;
    case EADDRNOTAVAIL:	prError = PR_ADDRESS_NOT_AVAILABLE_ERROR; break;
    case EAFNOSUPPORT:	prError = PR_ADDRESS_NOT_SUPPORTED_ERROR; break;
    case EAGAIN:	prError = PR_WOULD_BLOCK_ERROR; break;
    case EALREADY:	prError = PR_ALREADY_INITIATED_ERROR; break;
    case EBADF:		prError = PR_BAD_DESCRIPTOR_ERROR; break;
#ifdef EBADMSG
    case EBADMSG:	prError = PR_IO_ERROR; break;
#endif
    case EBUSY:		prError = PR_FILESYSTEM_MOUNTED_ERROR; break;
    case ECONNREFUSED:	prError = PR_CONNECT_REFUSED_ERROR; break;
    case ECONNRESET:	prError = PR_CONNECT_RESET_ERROR; break;
    case EDEADLK:	prError = PR_DEADLOCK_ERROR; break;
#ifdef EDIRCORRUPTED
    case EDIRCORRUPTED:	prError = PR_DIRECTORY_CORRUPTED_ERROR; break;
#endif
#ifdef EDQUOT
    case EDQUOT:	prError = PR_NO_DEVICE_SPACE_ERROR; break;
#endif
    case EEXIST:	prError = PR_FILE_EXISTS_ERROR; break;
    case EFAULT:	prError = PR_ACCESS_FAULT_ERROR; break;
    case EFBIG:		prError = PR_FILE_TOO_BIG_ERROR; break;
    case EINPROGRESS:	prError = PR_IN_PROGRESS_ERROR; break;
    case EINTR:		prError = PR_PENDING_INTERRUPT_ERROR; break;
    case EINVAL:	prError = PR_INVALID_ARGUMENT_ERROR; break;
    case EIO:		prError = PR_IO_ERROR; break;
    case EISCONN:	prError = PR_IS_CONNECTED_ERROR; break;
    case EISDIR:	prError = PR_IS_DIRECTORY_ERROR; break;
    case ELOOP:		prError = PR_LOOP_ERROR; break;
    case EMFILE:	prError = PR_PROC_DESC_TABLE_FULL_ERROR; break;
    case EMLINK:	prError = PR_MAX_DIRECTORY_ENTRIES_ERROR; break;
    case EMSGSIZE:	prError = PR_INVALID_ARGUMENT_ERROR; break;
#ifdef EMULTIHOP
    case EMULTIHOP:	prError = PR_REMOTE_FILE_ERROR; break;
#endif
    case ENAMETOOLONG:	prError = PR_NAME_TOO_LONG_ERROR; break;
    case ENETUNREACH:	prError = PR_NETWORK_UNREACHABLE_ERROR; break;
    case ENFILE:	prError = PR_SYS_DESC_TABLE_FULL_ERROR; break;
#if !defined(SCO)
    case ENOBUFS:	prError = PR_INSUFFICIENT_RESOURCES_ERROR; break;
#endif
    case ENODEV:	prError = PR_FILE_NOT_FOUND_ERROR; break;
    case ENOENT:	prError = PR_FILE_NOT_FOUND_ERROR; break;
    case ENOLCK:	prError = PR_FILE_IS_LOCKED_ERROR; break;
#ifdef ENOLINK 
    case ENOLINK:	prError = PR_REMOTE_FILE_ERROR; break;
#endif
    case ENOMEM:	prError = PR_OUT_OF_MEMORY_ERROR; break;
    case ENOPROTOOPT:	prError = PR_INVALID_ARGUMENT_ERROR; break;
    case ENOSPC:	prError = PR_NO_DEVICE_SPACE_ERROR; break;
#ifdef ENOSR 
    case ENOSR:		prError = PR_INSUFFICIENT_RESOURCES_ERROR; break;
#endif
    case ENOTCONN:	prError = PR_NOT_CONNECTED_ERROR; break;
    case ENOTDIR:	prError = PR_NOT_DIRECTORY_ERROR; break;
    case ENOTSOCK:	prError = PR_NOT_SOCKET_ERROR; break;
    case ENXIO:		prError = PR_FILE_NOT_FOUND_ERROR; break;
    case EOPNOTSUPP:	prError = PR_NOT_TCP_SOCKET_ERROR; break;
#ifdef EOVERFLOW
    case EOVERFLOW:	prError = PR_BUFFER_OVERFLOW_ERROR; break;
#endif
    case EPERM:		prError = PR_NO_ACCESS_RIGHTS_ERROR; break;
    case EPIPE:		prError = PR_CONNECT_RESET_ERROR; break;
#ifdef EPROTO
    case EPROTO:	prError = PR_IO_ERROR; break;
#endif
    case EPROTONOSUPPORT: prError = PR_PROTOCOL_NOT_SUPPORTED_ERROR; break;
    case EPROTOTYPE:	prError = PR_ADDRESS_NOT_SUPPORTED_ERROR; break;
    case ERANGE:	prError = PR_INVALID_METHOD_ERROR; break;
    case EROFS:		prError = PR_READ_ONLY_FILESYSTEM_ERROR; break;
    case ESPIPE:	prError = PR_INVALID_METHOD_ERROR; break;
    case ETIMEDOUT:	prError = PR_IO_TIMEOUT_ERROR; break;
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:	prError = PR_WOULD_BLOCK_ERROR; break;
#endif
    case EXDEV:		prError = PR_NOT_SAME_DEVICE_ERROR; break;

    default:		prError = PR_UNKNOWN_ERROR; break;
    }
    PR_SetError(prError, err);
}

#endif
