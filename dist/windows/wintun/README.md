# [Wintun Network Adapter](https://www.wintun.net/)
### TUN Device Driver for Windows

This is a layer 3 TUN driver for Windows 7, 8, 8.1, and 10. Originally created for [WireGuard](https://www.wireguard.com/), it is intended to be useful to a wide variety of projects that require layer 3 tunneling devices with implementations primarily in userspace.

## Installation

Wintun is deployed as a platform-specific `wintun.dll` file. Install the `wintun.dll` file side-by-side with your application. Download the dll from [wintun.net](https://www.wintun.net/), alongside the header file for your application described below.

## Usage

Include the [`wintun.h` file](https://git.zx2c4.com/wintun/tree/api/wintun.h) in your project simply by copying it there and dynamically load the `wintun.dll` using [`LoadLibraryEx()`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa) and [`GetProcAddress()`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) to resolve each function, using the typedefs provided in the header file. The [`InitializeWintun` function in the example.c code](https://git.zx2c4.com/wintun/tree/example/example.c) provides this in a function that you can simply copy and paste.

With the library setup, Wintun can then be used by first creating an adapter, configuring it, and then setting its status to "up". Adapters have names (e.g. "OfficeNet") and types (e.g. "Wintun").

```C
WINTUN_ADAPTER_HANDLE Adapter1 = WintunCreateAdapter(L"OfficeNet", L"Wintun", &SomeFixedGUID1);
WINTUN_ADAPTER_HANDLE Adapter2 = WintunCreateAdapter(L"HomeNet", L"Wintun", &SomeFixedGUID2);
WINTUN_ADAPTER_HANDLE Adapter3 = WintunCreateAdapter(L"Data Center", L"Wintun", &SomeFixedGUID3);
```

After creating an adapter, we can use it by starting a session:

```C
WINTUN_SESSION_HANDLE Session = WintunStartSession(Adapter2, 0x400000);
```

Then, the `WintunAllocateSendPacket` and `WintunSendPacket` functions can be used for sending packets ([used by `SendPackets` in the example.c code](https://git.zx2c4.com/wintun/tree/example/example.c)):

```C
BYTE *OutgoingPacket = WintunAllocateSendPacket(Session, PacketDataSize);
if (OutgoingPacket)
{
    memcpy(OutgoingPacket, PacketData, PacketDataSize);
    WintunSendPacket(Session, OutgoingPacket);
}
else if (GetLastError() != ERROR_BUFFER_OVERFLOW) // Silently drop packets if the ring is full
    Log(L"Packet write failed");
```

And the `WintunReceivePacket` and `WintunReleaseReceivePacket` functions can be used for receiving packets ([used by `ReceivePackets` in the example.c code](https://git.zx2c4.com/wintun/tree/example/example.c)):

```C
for (;;)
{
    DWORD IncomingPacketSize;
    BYTE *IncomingPacket = WintunReceivePacket(Session, &IncomingPacketSize);
    if (IncomingPacket)
    {
        DoSomethingWithPacket(IncomingPacket, IncomingPacketSize);
        WintunReleaseReceivePacket(Session, IncomingPacket);
    }
    else if (GetLastError() == ERROR_NO_MORE_ITEMS)
        WaitForSingleObject(WintunGetReadWaitEvent(Session), INFINITE);
    else
    {
        Log(L"Packet read failed");
        break;
    }
}
```

Some high performance use cases may want to spin on `WintunReceivePackets` for a number of cycles before falling back to waiting on the read-wait event.

You are **highly encouraged** to read the [**example.c short example**](https://git.zx2c4.com/wintun/tree/example/example.c) to see how to put together a simple userspace network tunnel.

The various functions and definitions are [documented in the reference below](#Reference).

## Reference

### Macro Definitions

#### WINTUN\_MAX\_POOL

`#define WINTUN_MAX_POOL   256`

Maximum pool name length including zero terminator

#### WINTUN\_MIN\_RING\_CAPACITY

`#define WINTUN_MIN_RING_CAPACITY   0x20000 /* 128kiB */`

Minimum ring capacity.

#### WINTUN\_MAX\_RING\_CAPACITY

`#define WINTUN_MAX_RING_CAPACITY   0x4000000 /* 64MiB */`

Maximum ring capacity.

#### WINTUN\_MAX\_IP\_PACKET\_SIZE

`#define WINTUN_MAX_IP_PACKET_SIZE   0xFFFF`

Maximum IP packet size

### Typedefs

#### WINTUN\_ADAPTER\_HANDLE

`typedef void* WINTUN_ADAPTER_HANDLE`

A handle representing Wintun adapter

#### WINTUN\_ENUM\_CALLBACK

`typedef BOOL(* WINTUN_ENUM_CALLBACK) (WINTUN_ADAPTER_HANDLE Adapter, LPARAM Param)`

Called by WintunEnumAdapters for each adapter in the pool.

**Parameters**

- *Adapter*: Adapter handle, which will be freed when this function returns.
- *Param*: An application-defined value passed to the WintunEnumAdapters.

**Returns**

Non-zero to continue iterating adapters; zero to stop.

#### WINTUN\_LOGGER\_CALLBACK

`typedef void(* WINTUN_LOGGER_CALLBACK) (WINTUN_LOGGER_LEVEL Level, DWORD64 Timestamp, const WCHAR *Message)`

Called by internal logger to report diagnostic messages

**Parameters**

- *Level*: Message level.
- *Timestamp*: Message timestamp in in 100ns intervals since 1601-01-01 UTC.
- *Message*: Message text.

#### WINTUN\_SESSION\_HANDLE

`typedef void* WINTUN_SESSION_HANDLE`

A handle representing Wintun session

### Enumeration Types

#### WINTUN\_LOGGER\_LEVEL

`enum WINTUN_LOGGER_LEVEL`

Determines the level of logging, passed to WINTUN\_LOGGER\_CALLBACK.

- *WINTUN\_LOG\_INFO*: Informational
- *WINTUN\_LOG\_WARN*: Warning
- *WINTUN\_LOG\_ERR*: Error

Enumerator

### Functions

#### WintunCreateAdapter()

`WINTUN_ADAPTER_HANDLE WintunCreateAdapter (const WCHAR * Name, const WCHAR * TunnelType, const GUID * RequestedGUID)`

Creates a new Wintun adapter.

**Parameters**

- *Name*: The requested name of the adapter. Zero-terminated string of up to MAX\_ADAPTER\_NAME-1 characters.
- *Name*: Name of the adapter tunnel type. Zero-terminated string of up to MAX\_ADAPTER\_NAME-1 characters.
- *RequestedGUID*: The GUID of the created network adapter, which then influences NLA generation deterministically. If it is set to NULL, the GUID is chosen by the system at random, and hence a new NLA entry is created for each new adapter. It is called "requested" GUID because the API it uses is completely undocumented, and so there could be minor interesting complications with its usage.

**Returns**

If the function succeeds, the return value is the adapter handle. Must be released with WintunCloseAdapter. If the function fails, the return value is NULL. To get extended error information, call GetLastError.

#### WintunOpenAdapter()

`WINTUN_ADAPTER_HANDLE WintunOpenAdapter (const WCHAR * Name)`

Opens an existing Wintun adapter.

**Parameters**

- *Name*: The requested name of the adapter. Zero-terminated string of up to MAX\_ADAPTER\_NAME-1 characters.

**Returns**

If the function succeeds, the return value is adapter handle. Must be released with WintunCloseAdapter. If the function fails, the return value is NULL. To get extended error information, call GetLastError.

#### WintunCloseAdapter()

`void WintunCloseAdapter (WINTUN_ADAPTER_HANDLE Adapter)`

Releases Wintun adapter resources and, if adapter was created with WintunCreateAdapter, removes adapter.

**Parameters**

- *Adapter*: Adapter handle obtained with WintunCreateAdapter or WintunOpenAdapter.

#### WintunDeleteDriver()

`BOOL WintunDeleteDriver ()`

Deletes the Wintun driver if there are no more adapters in use.

**Returns**

If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To get extended error information, call GetLastError.

#### WintunGetAdapterLuid()

`void WintunGetAdapterLuid (WINTUN_ADAPTER_HANDLE Adapter, NET_LUID * Luid)`

Returns the LUID of the adapter.

**Parameters**

- *Adapter*: Adapter handle obtained with WintunOpenAdapter or WintunCreateAdapter
- *Luid*: Pointer to LUID to receive adapter LUID.

#### WintunGetRunningDriverVersion()

`DWORD WintunGetRunningDriverVersion (void )`

Determines the version of the Wintun driver currently loaded.

**Returns**

If the function succeeds, the return value is the version number. If the function fails, the return value is zero. To get extended error information, call GetLastError. Possible errors include the following: ERROR\_FILE\_NOT\_FOUND Wintun not loaded

#### WintunSetLogger()

`void WintunSetLogger (WINTUN_LOGGER_CALLBACK NewLogger)`

Sets logger callback function.

**Parameters**

- *NewLogger*: Pointer to callback function to use as a new global logger. NewLogger may be called from various threads concurrently. Should the logging require serialization, you must handle serialization in NewLogger. Set to NULL to disable.

#### WintunStartSession()

`WINTUN_SESSION_HANDLE WintunStartSession (WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity)`

Starts Wintun session.

**Parameters**

- *Adapter*: Adapter handle obtained with WintunOpenAdapter or WintunCreateAdapter
- *Capacity*: Rings capacity. Must be between WINTUN\_MIN\_RING\_CAPACITY and WINTUN\_MAX\_RING\_CAPACITY (incl.) Must be a power of two.

**Returns**

Wintun session handle. Must be released with WintunEndSession. If the function fails, the return value is NULL. To get extended error information, call GetLastError.

#### WintunEndSession()

`void WintunEndSession (WINTUN_SESSION_HANDLE Session)`

Ends Wintun session.

**Parameters**

- *Session*: Wintun session handle obtained with WintunStartSession

#### WintunGetReadWaitEvent()

`HANDLE WintunGetReadWaitEvent (WINTUN_SESSION_HANDLE Session)`

Gets Wintun session's read-wait event handle.

**Parameters**

- *Session*: Wintun session handle obtained with WintunStartSession

**Returns**

Pointer to receive event handle to wait for available data when reading. Should WintunReceivePackets return ERROR\_NO\_MORE\_ITEMS (after spinning on it for a while under heavy load), wait for this event to become signaled before retrying WintunReceivePackets. Do not call CloseHandle on this event - it is managed by the session.

#### WintunReceivePacket()

`BYTE* WintunReceivePacket (WINTUN_SESSION_HANDLE Session, DWORD * PacketSize)`

Retrieves one or packet. After the packet content is consumed, call WintunReleaseReceivePacket with Packet returned from this function to release internal buffer. This function is thread-safe.

**Parameters**

- *Session*: Wintun session handle obtained with WintunStartSession
- *PacketSize*: Pointer to receive packet size.

**Returns**

Pointer to layer 3 IPv4 or IPv6 packet. Client may modify its content at will. If the function fails, the return value is NULL. To get extended error information, call GetLastError. Possible errors include the following: ERROR\_HANDLE\_EOF Wintun adapter is terminating; ERROR\_NO\_MORE\_ITEMS Wintun buffer is exhausted; ERROR\_INVALID\_DATA Wintun buffer is corrupt

#### WintunReleaseReceivePacket()

`void WintunReleaseReceivePacket (WINTUN_SESSION_HANDLE Session, const BYTE * Packet)`

Releases internal buffer after the received packet has been processed by the client. This function is thread-safe.

**Parameters**

- *Session*: Wintun session handle obtained with WintunStartSession
- *Packet*: Packet obtained with WintunReceivePacket

#### WintunAllocateSendPacket()

`BYTE* WintunAllocateSendPacket (WINTUN_SESSION_HANDLE Session, DWORD PacketSize)`

Allocates memory for a packet to send. After the memory is filled with packet data, call WintunSendPacket to send and release internal buffer. WintunAllocateSendPacket is thread-safe and the WintunAllocateSendPacket order of calls define the packet sending order.

**Parameters**

- *Session*: Wintun session handle obtained with WintunStartSession
- *PacketSize*: Exact packet size. Must be less or equal to WINTUN\_MAX\_IP\_PACKET\_SIZE.

**Returns**

Returns pointer to memory where to prepare layer 3 IPv4 or IPv6 packet for sending. If the function fails, the return value is NULL. To get extended error information, call GetLastError. Possible errors include the following: ERROR\_HANDLE\_EOF Wintun adapter is terminating; ERROR\_BUFFER\_OVERFLOW Wintun buffer is full;

#### WintunSendPacket()

`void WintunSendPacket (WINTUN_SESSION_HANDLE Session, const BYTE * Packet)`

Sends the packet and releases internal buffer. WintunSendPacket is thread-safe, but the WintunAllocateSendPacket order of calls define the packet sending order. This means the packet is not guaranteed to be sent in the WintunSendPacket yet.

**Parameters**

- *Session*: Wintun session handle obtained with WintunStartSession
- *Packet*: Packet obtained with WintunAllocateSendPacket

## Building

**Do not distribute drivers or files named "Wintun", as they will most certainly clash with official deployments. Instead distribute [`wintun.dll` as downloaded from wintun.net](https://www.wintun.net).**

General requirements:

- [Visual Studio 2019](https://visualstudio.microsoft.com/downloads/) with Windows SDK
- [Windows Driver Kit](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

`wintun.sln` may be opened in Visual Studio for development and building. Be sure to run `bcdedit /set testsigning on` and then reboot before to enable unsigned driver loading. The default run sequence (F5) in Visual Studio will build the example project and its dependencies.

## License

The entire contents of [the repository](https://git.zx2c4.com/wintun/), including all documentation and example code, is "Copyright © 2018-2021 WireGuard LLC. All Rights Reserved." Source code is licensed under the [GPLv2](COPYING). Prebuilt binaries from [wintun.net](https://www.wintun.net/) are released under a more permissive license suitable for more forms of software contained inside of the .zip files distributed there.
