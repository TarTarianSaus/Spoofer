#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntdef.h>
#include <windef.h>
#include <Ntstrsafe.h>
#include <stdlib.h>
#include <intrin.h>
#include <ntddscsi.h>
#include <ntdddisk.h>
#include <ata.h>
#include <classpnp.h>
#include <wchar.h>
#include "Structures.h"
#include <initguid.h>

//#define DEBUG_PRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

DEFINE_GUID(GUID_DEVINTERFACE_NET, 0xcac88484, 0x7515, 0x4c03, 0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61);

PERESOURCE PiDDBLock;
PRTL_AVL_TABLE PiDDBCacheTable;
void* PspCidTable;

struct PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16];
};


typedef char byte;
typedef INT8 int8_t;
typedef INT16 int16_t;
typedef INT32 int32_t;
typedef INT64 int64_t;
typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef UINT64 uintptr_t;

namespace Globals
{
	PLIST_ENTRY g_PsLoadedModuleList;
	uintptr_t g_KernelBase;
	size_t g_KernelSize;
	int g_randomNumber = 32;
};

typedef enum _WinVer
{
	WINVER_7 = 0x0610,
	WINVER_7_SP1 = 0x0611,
	WINVER_8 = 0x0620,
	WINVER_81 = 0x0630,
	WINVER_10 = 0x0A00,
	WINVER_10_RS1 = 0x0A01,
	WINVER_10_RS2 = 0x0A02,
	WINVER_10_RS3 = 0x0A03,
	WINVER_10_RS4 = 0x0A04,
} WinVer;

typedef struct _DYNAMIC_DATA
{
	////// mac //////
	ULONG IfBlock1;
	ULONG IfBlock2;
	ULONG Miniport;
	ULONG NextFilter;
	ULONG ndisGlobalFilterList;
	ULONG PermanentPhysAddress;
	////// hdd //////
	ULONG Raidserial;
} DYNAMIC_DATA, * PDYNAMIC_DATA;

DYNAMIC_DATA dynData;


typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

EXTERN_C_START

extern POBJECT_TYPE* IoDriverObjectType;
NTKERNELAPI NTSTATUS ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID* Object);
PIMAGE_NT_HEADERS64 RtlImageNtHeader(PVOID Base);
EXTERN_C_END