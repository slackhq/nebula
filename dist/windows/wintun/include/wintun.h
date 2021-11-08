/* SPDX-License-Identifier: GPL-2.0 OR MIT
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <winsock2.h>
#include <windows.h>
#include <ipexport.h>
#include <ifdef.h>
#include <ws2ipdef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ALIGNED
#    if defined(_MSC_VER)
#        define ALIGNED(n) __declspec(align(n))
#    elif defined(__GNUC__)
#        define ALIGNED(n) __attribute__((aligned(n)))
#    else
#        error "Unable to define ALIGNED"
#    endif
#endif

/* MinGW is missing this one, unfortunately. */
#ifndef _Post_maybenull_
#    define _Post_maybenull_
#endif

#pragma warning(push)
#pragma warning(disable : 4324) /* structure was padded due to alignment specifier */

/**
 * A handle representing Wintun adapter
 */
typedef struct _WINTUN_ADAPTER *WINTUN_ADAPTER_HANDLE;

/**
 * Creates a new Wintun adapter.
 *
 * @param Name          The requested name of the adapter. Zero-terminated string of up to MAX_ADAPTER_NAME-1
 *                      characters.
 *
 * @param TunnelType    Name of the adapter tunnel type. Zero-terminated string of up to MAX_ADAPTER_NAME-1
 *                      characters.
 *
 * @param RequestedGUID The GUID of the created network adapter, which then influences NLA generation deterministically.
 *                      If it is set to NULL, the GUID is chosen by the system at random, and hence a new NLA entry is
 *                      created for each new adapter. It is called "requested" GUID because the API it uses is
 *                      completely undocumented, and so there could be minor interesting complications with its usage.
 *
 * @return If the function succeeds, the return value is the adapter handle. Must be released with
 * WintunCloseAdapter. If the function fails, the return value is NULL. To get extended error information, call
 * GetLastError.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
WINTUN_ADAPTER_HANDLE(WINAPI WINTUN_CREATE_ADAPTER_FUNC)
(_In_z_ LPCWSTR Name, _In_z_ LPCWSTR TunnelType, _In_opt_ const GUID *RequestedGUID);

/**
 * Opens an existing Wintun adapter.
 *
 * @param Name          The requested name of the adapter. Zero-terminated string of up to MAX_ADAPTER_NAME-1
 *                      characters.
 *
 * @return If the function succeeds, the return value is the adapter handle. Must be released with
 * WintunCloseAdapter. If the function fails, the return value is NULL. To get extended error information, call
 * GetLastError.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
WINTUN_ADAPTER_HANDLE(WINAPI WINTUN_OPEN_ADAPTER_FUNC)(_In_z_ LPCWSTR Name);

/**
 * Releases Wintun adapter resources and, if adapter was created with WintunCreateAdapter, removes adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunCreateAdapter or WintunOpenAdapter.
 */
typedef VOID(WINAPI WINTUN_CLOSE_ADAPTER_FUNC)(_In_opt_ WINTUN_ADAPTER_HANDLE Adapter);

/**
 * Deletes the Wintun driver if there are no more adapters in use.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI WINTUN_DELETE_DRIVER_FUNC)(VOID);

/**
 * Returns the LUID of the adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunCreateAdapter or WintunOpenAdapter
 *
 * @param Luid          Pointer to LUID to receive adapter LUID.
 */
typedef VOID(WINAPI WINTUN_GET_ADAPTER_LUID_FUNC)(_In_ WINTUN_ADAPTER_HANDLE Adapter, _Out_ NET_LUID *Luid);

/**
 * Determines the version of the Wintun driver currently loaded.
 *
 * @return If the function succeeds, the return value is the version number. If the function fails, the return value is
 *         zero. To get extended error information, call GetLastError. Possible errors include the following:
 *         ERROR_FILE_NOT_FOUND  Wintun not loaded
 */
typedef _Return_type_success_(return != 0)
DWORD(WINAPI WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC)(VOID);

/**
 * Determines the level of logging, passed to WINTUN_LOGGER_CALLBACK.
 */
typedef enum
{
    WINTUN_LOG_INFO, /**< Informational */
    WINTUN_LOG_WARN, /**< Warning */
    WINTUN_LOG_ERR   /**< Error */
} WINTUN_LOGGER_LEVEL;

/**
 * Called by internal logger to report diagnostic messages
 *
 * @param Level         Message level.
 *
 * @param Timestamp     Message timestamp in in 100ns intervals since 1601-01-01 UTC.
 *
 * @param Message       Message text.
 */
typedef VOID(CALLBACK *WINTUN_LOGGER_CALLBACK)(
    _In_ WINTUN_LOGGER_LEVEL Level,
    _In_ DWORD64 Timestamp,
    _In_z_ LPCWSTR Message);

/**
 * Sets logger callback function.
 *
 * @param NewLogger     Pointer to callback function to use as a new global logger. NewLogger may be called from various
 *                      threads concurrently. Should the logging require serialization, you must handle serialization in
 *                      NewLogger. Set to NULL to disable.
 */
typedef VOID(WINAPI WINTUN_SET_LOGGER_FUNC)(_In_ WINTUN_LOGGER_CALLBACK NewLogger);

/**
 * Minimum ring capacity.
 */
#define WINTUN_MIN_RING_CAPACITY 0x20000 /* 128kiB */

/**
 * Maximum ring capacity.
 */
#define WINTUN_MAX_RING_CAPACITY 0x4000000 /* 64MiB */

/**
 * A handle representing Wintun session
 */
typedef struct _TUN_SESSION *WINTUN_SESSION_HANDLE;

/**
 * Starts Wintun session.
 *
 * @param Adapter       Adapter handle obtained with WintunOpenAdapter or WintunCreateAdapter
 *
 * @param Capacity      Rings capacity. Must be between WINTUN_MIN_RING_CAPACITY and WINTUN_MAX_RING_CAPACITY (incl.)
 *                      Must be a power of two.
 *
 * @return Wintun session handle. Must be released with WintunEndSession. If the function fails, the return value is
 *         NULL. To get extended error information, call GetLastError.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
WINTUN_SESSION_HANDLE(WINAPI WINTUN_START_SESSION_FUNC)(_In_ WINTUN_ADAPTER_HANDLE Adapter, _In_ DWORD Capacity);

/**
 * Ends Wintun session.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 */
typedef VOID(WINAPI WINTUN_END_SESSION_FUNC)(_In_ WINTUN_SESSION_HANDLE Session);

/**
 * Gets Wintun session's read-wait event handle.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @return Pointer to receive event handle to wait for available data when reading. Should
 *         WintunReceivePackets return ERROR_NO_MORE_ITEMS (after spinning on it for a while under heavy
 *         load), wait for this event to become signaled before retrying WintunReceivePackets. Do not call
 *         CloseHandle on this event - it is managed by the session.
 */
typedef HANDLE(WINAPI WINTUN_GET_READ_WAIT_EVENT_FUNC)(_In_ WINTUN_SESSION_HANDLE Session);

/**
 * Maximum IP packet size
 */
#define WINTUN_MAX_IP_PACKET_SIZE 0xFFFF

/**
 * Retrieves one or packet. After the packet content is consumed, call WintunReleaseReceivePacket with Packet returned
 * from this function to release internal buffer. This function is thread-safe.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @param PacketSize    Pointer to receive packet size.
 *
 * @return Pointer to layer 3 IPv4 or IPv6 packet. Client may modify its content at will. If the function fails, the
 *         return value is NULL. To get extended error information, call GetLastError. Possible errors include the
 *         following:
 *         ERROR_HANDLE_EOF     Wintun adapter is terminating;
 *         ERROR_NO_MORE_ITEMS  Wintun buffer is exhausted;
 *         ERROR_INVALID_DATA   Wintun buffer is corrupt
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
_Post_writable_byte_size_(*PacketSize)
BYTE *(WINAPI WINTUN_RECEIVE_PACKET_FUNC)(_In_ WINTUN_SESSION_HANDLE Session, _Out_ DWORD *PacketSize);

/**
 * Releases internal buffer after the received packet has been processed by the client. This function is thread-safe.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @param Packet        Packet obtained with WintunReceivePacket
 */
typedef VOID(
    WINAPI WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(_In_ WINTUN_SESSION_HANDLE Session, _In_ const BYTE *Packet);

/**
 * Allocates memory for a packet to send. After the memory is filled with packet data, call WintunSendPacket to send
 * and release internal buffer. WintunAllocateSendPacket is thread-safe and the WintunAllocateSendPacket order of
 * calls define the packet sending order.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @param PacketSize    Exact packet size. Must be less or equal to WINTUN_MAX_IP_PACKET_SIZE.
 *
 * @return Returns pointer to memory where to prepare layer 3 IPv4 or IPv6 packet for sending. If the function fails,
 *         the return value is NULL. To get extended error information, call GetLastError. Possible errors include the
 *         following:
 *         ERROR_HANDLE_EOF       Wintun adapter is terminating;
 *         ERROR_BUFFER_OVERFLOW  Wintun buffer is full;
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
_Post_writable_byte_size_(PacketSize)
BYTE *(WINAPI WINTUN_ALLOCATE_SEND_PACKET_FUNC)(_In_ WINTUN_SESSION_HANDLE Session, _In_ DWORD PacketSize);

/**
 * Sends the packet and releases internal buffer. WintunSendPacket is thread-safe, but the WintunAllocateSendPacket
 * order of calls define the packet sending order. This means the packet is not guaranteed to be sent in the
 * WintunSendPacket yet.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @param Packet        Packet obtained with WintunAllocateSendPacket
 */
typedef VOID(WINAPI WINTUN_SEND_PACKET_FUNC)(_In_ WINTUN_SESSION_HANDLE Session, _In_ const BYTE *Packet);

#pragma warning(pop)

#ifdef __cplusplus
}
#endif
