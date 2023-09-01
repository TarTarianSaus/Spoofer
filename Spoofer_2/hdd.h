#pragma once

namespace Hdd
{
	typedef __int64(__fastcall* RaidUnitRegisterInterfaces)(PVOID);
	RaidUnitRegisterInterfaces pRaidUnitRegisterInterfaces;

	typedef NTSTATUS(__fastcall* DiskEnableDisableFailurePrediction)(PFUNCTIONAL_DEVICE_EXTENSION, BOOLEAN);
	DiskEnableDisableFailurePrediction pDiskEnableDisableFailurePrediction;

	void Spoof()
	{
		
		NTSTATUS status;

		UNICODE_STRING disk_driver_name = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
		PDRIVER_OBJECT disk_driver_object = nullptr;
		auto disk_status = ObReferenceObjectByName
		(
			&disk_driver_name,
			OBJ_CASE_INSENSITIVE,
			nullptr,
			0,
			*IoDriverObjectType,
			KernelMode,
			nullptr,
			reinterpret_cast<PVOID*>(&disk_driver_object)
		);


		if (NT_SUCCESS(disk_status))
		{
			MODULEINFO Disk_Info = Utils::get_system_module_info(disk_driver_object->DriverSection);
			MODULEINFO Storport_Info = Utils::get_system_module_info(L"storport.sys");

			pDiskEnableDisableFailurePrediction = reinterpret_cast<DiskEnableDisableFailurePrediction>(Utils::FindSignatureIDA("48 89 5C 24 ? 48 89 74 24 ? 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B 59 60 48 8B F1 40 8A FA 8B 4B 10", reinterpret_cast<unsigned char*>(Disk_Info.lpBaseOfDll), Disk_Info.SizeOfImage, 0x7FFFFFFF));
			
			auto address = Utils::FindSignatureIDA("E8 ? ? ? ? 48 8B CB E8 ? ? ? ? 85 C0 74 0A", reinterpret_cast<unsigned char*>(Storport_Info.lpBaseOfDll), Storport_Info.SizeOfImage, 0x7FFFFFFF);
			pRaidUnitRegisterInterfaces = reinterpret_cast<RaidUnitRegisterInterfaces>(address + 5 + *(int32_t*)(address + 1));

			ULONG DeviceObjectCount = 0;
			status = IoEnumerateDeviceObjectList(disk_driver_object, NULL, 0, &DeviceObjectCount);


			PDEVICE_OBJECT m_Devices[10];
			status = IoEnumerateDeviceObjectList(disk_driver_object, m_Devices, DeviceObjectCount * sizeof(PDEVICE_OBJECT), &DeviceObjectCount);


			for (int i = 0; i < DeviceObjectCount; i++)
			{
				PDEVICE_OBJECT m_Device = m_Devices[i];

				if (m_Device)
				{
					PFUNCTIONAL_DEVICE_EXTENSION FdoExtension = reinterpret_cast<PFUNCTIONAL_DEVICE_EXTENSION>(m_Device->DeviceExtension);

					if (FdoExtension)
					{
						PDEVICE_OBJECT filesystemDevice = (PDEVICE_OBJECT)IoGetDeviceAttachmentBaseRef(m_Device);

						if (filesystemDevice && filesystemDevice->DeviceType == FILE_DEVICE_DISK)
						{
							STRING Raidserial = *(STRING*)((uint64_t)filesystemDevice->DeviceExtension + dynData.Raidserial);
							PCHAR Fdoserial = (PCHAR)FdoExtension->DeviceDescriptor + FdoExtension->DeviceDescriptor->SerialNumberOffset;

							Utils::RandomizeSerialNumber(Fdoserial, Globals::g_randomNumber);

							Raidserial.Length = strlen(Fdoserial);
							memset(Raidserial.Buffer, 0, Raidserial.Length);
							memcpy(Raidserial.Buffer, Fdoserial, Raidserial.Length);

							pRaidUnitRegisterInterfaces(filesystemDevice->DeviceExtension);		
							pDiskEnableDisableFailurePrediction(FdoExtension, FALSE);
						}
					}
				}
			}
		}

	}
}
