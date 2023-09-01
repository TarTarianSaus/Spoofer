#include "Defines.h"
#include "Utils.h"
#include "hdd.h"
#include <ndis.h>

#define DEVICE_NAME     L"\\Device\\asdasdasdq23"
#define DOS_DEVICE_NAME L"\\DosDevices\\asdasdasdq23"


NTSTATUS InitDynamicData(PDYNAMIC_DATA pData)
{
	NTSTATUS status = STATUS_SUCCESS;
	RTL_OSVERSIONINFOEXW verInfo = { 0 };

	if (pData == NULL)
		return STATUS_INVALID_ADDRESS;

	RtlZeroMemory(pData, sizeof(DYNAMIC_DATA));

	verInfo.dwOSVersionInfoSize = sizeof(verInfo);
	status = RtlGetVersion((PRTL_OSVERSIONINFOW)& verInfo);

	if (status == STATUS_SUCCESS)
	{
		status = STATUS_NOT_SUPPORTED;
		ULONG ver_short = (verInfo.dwMajorVersion << 8) | (verInfo.dwMinorVersion << 4) | verInfo.wServicePackMajor;

		if (ver_short != WINVER_10)
			return status;

		switch (verInfo.dwBuildNumber)
		{
		case 17134:
			pData->IfBlock1 = 0x348;
			pData->IfBlock2 = 0xFE0;
			pData->Miniport = 0x20;
			pData->NextFilter = 0x008;
			pData->ndisGlobalFilterList = 0x99138; //48 8D 15 ? ? ? ? 44 8A C0
			pData->PermanentPhysAddress = 0x486;
			pData->Raidserial = 0x068;
			status = STATUS_SUCCESS;
			break;
		case 17763:
			pData->IfBlock1 = 0x2C0;
			pData->IfBlock2 = 0xFE8;
			pData->Miniport = 0x020;
			pData->NextFilter = 0x008;
			pData->ndisGlobalFilterList = 0xA0700; //48 8D 15 ? ? ? ? 44 8A C0
			pData->PermanentPhysAddress = 0x486;
			pData->Raidserial = 0x070;
			status = STATUS_SUCCESS;
			break;
		case 18362:
			pData->IfBlock1 = 0x2B8;
			pData->IfBlock2 = 0xFC8;
			pData->Miniport = 0x020;
			pData->NextFilter = 0x008;
			pData->ndisGlobalFilterList = 0xE6768; //48 8D 15 ? ? ? ? 44 8A C0
			pData->PermanentPhysAddress = 0x486;
			pData->Raidserial = 0x070;
			status = STATUS_SUCCESS;
			break;
		default:
			break;
		}
	}

	{
		auto address = Utils::FindSignatureIDA("E8 ? ? ? ? 8B D8 3D ? ? ? ? 75 1A 4C 8B 8C 24 ? ? ? ?", reinterpret_cast<unsigned char*>(Globals::g_KernelBase), Globals::g_KernelSize, 0x7FFFFFFF);
		if (address)
		{
			address -= 0x1C;
			auto offset = *reinterpret_cast<int32_t*>(address + 3);
			PiDDBLock = reinterpret_cast<PERESOURCE>(address + 7 + offset);
		}
		else
			return STATUS_NOT_SUPPORTED;
	}
	{
		auto address = Utils::FindSignatureIDA("48 8D 0D ? ? ? ? 66 89 54 24 ? 66 89 54 24 ?", reinterpret_cast<unsigned char*>(Globals::g_KernelBase), Globals::g_KernelSize, 0x7FFFFFFF);
		if (address)
		{
			auto offset = *reinterpret_cast<int32_t*>(address + 3);
			PiDDBCacheTable = reinterpret_cast<PRTL_AVL_TABLE>(address + 7 + offset);
		}
		else
			return STATUS_NOT_SUPPORTED;
	}

	{
		auto address = Utils::FindSignatureIDA("48 8B 0D ? ? ? ? E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 48 8B 97 ? ? ? ?", reinterpret_cast<unsigned char*>(Globals::g_KernelBase), Globals::g_KernelSize, 0x7FFFFFFF);

		if (address)
		{
			auto offset = *reinterpret_cast<int32_t*>(address + 3);
			PspCidTable = reinterpret_cast<void*>(address + 7 + offset);
		}
		else
			return STATUS_NOT_SUPPORTED;
	}

	return status;
};

bool clean_Piddb(PiDDBCacheEntry entry)
{
	ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

	auto found_entry = (PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &entry);

	if (!found_entry)
	{
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	RemoveEntryList(&found_entry->List);

	if (!RtlDeleteElementGenericTableAvl(PiDDBCacheTable, found_entry))
	{
		ExReleaseResourceLite(PiDDBLock);
		return false;
	}

	bool removed_entry = !RtlLookupElementGenericTableAvl(PiDDBCacheTable, &entry);

	ExReleaseResourceLite(PiDDBLock);

	return removed_entry;
}

bool clean_driver_info(PDRIVER_OBJECT driver_obj)
{
	PLDR_DATA_TABLE_ENTRY ldr_data = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(driver_obj->DriverSection);

	PIMAGE_NT_HEADERS64 nt_headers = RtlImageNtHeader(ldr_data->DllBase);

	if (!nt_headers)
		return false;

	PiDDBCacheEntry lookup_entry = {};
	lookup_entry.DriverName = ldr_data->BaseDllName;
	lookup_entry.TimeDateStamp = nt_headers->FileHeader.TimeDateStamp;

	bool removed_entry = clean_Piddb(lookup_entry);

	if (removed_entry)
	{
		ldr_data->BaseDllName.Buffer[0] = L'\0';
		ldr_data->BaseDllName.Length = 0;
		ldr_data->BaseDllName.MaximumLength = 0;
	}

	return removed_entry;
}


VOID QCUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING device_link_unicode_str;
	RtlUnicodeStringInit(&device_link_unicode_str, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&device_link_unicode_str);

	if (!clean_driver_info(DriverObject))
		KeBugCheck(DRIVER_VIOLATION);

	IoDeleteDevice(DriverObject->DeviceObject);
	return;
}


NTSTATUS QCDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;

	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	PDEVICE_OBJECT deviceObject = NULL;
	UNICODE_STRING deviceName;
	UNICODE_STRING deviceLink;

	ULONG seed = KeQueryTimeIncrement();
	Globals::g_randomNumber = RtlRandomEx(&seed) % 255;

	NTSTATUS status = Utils::init_ldr_data();

	if (!NT_SUCCESS(status))
		return status;

	status = InitDynamicData(&dynData);

	if (!NT_SUCCESS(status))
		return status;

	RtlUnicodeStringInit(&deviceName, DEVICE_NAME);
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);

	if (!NT_SUCCESS(status))
		return status;

	DriverObject->MajorFunction[IRP_MJ_CREATE] =
	DriverObject->MajorFunction[IRP_MJ_CLOSE] =
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = QCDispatch;
	DriverObject->DriverUnload = QCUnload;

	RtlUnicodeStringInit(&deviceLink, DOS_DEVICE_NAME);

	status = IoCreateSymbolicLink(&deviceLink, &deviceName);

	if (!NT_SUCCESS(status))
		IoDeleteDevice(deviceObject);

	Hdd::Spoof();
	return status;
}