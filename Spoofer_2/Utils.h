#pragma once

namespace Utils
{
	template <typename Type>
	Type alloc_kernel_mem(size_t size)
	{
		return reinterpret_cast<Type>(ExAllocatePool(NonPagedPool, size));
	}

	void free_kernel_mem(void* addr)
	{
		ExFreePool(addr);
	}

	uintptr_t find_cave(MODULEINFO mod_info, size_t size)
	{
		auto base = reinterpret_cast<uintptr_t>(mod_info.lpBaseOfDll);
		size_t count = 0;
		for (uintptr_t offset = 0x1000; offset < mod_info.SizeOfImage; offset++)
		{
			const auto byte = *reinterpret_cast<PBYTE>(base + offset);
			if (byte == 0x0 || byte == 0x90)
				count++;
			else
				count = 0;

			if (count == size + 8)
				return base + offset - count + 8;
		}
		return 0x0;
	}

	VOID set_protection(BOOLEAN set)
	{
		if (!set)
		{
			_disable();
			__writecr0(__readcr0() & ~0x10000);
		}
		else
		{
			__writecr0(__readcr0() | 0x10000);
			_enable();
		}
	}

	char hexify(int x) {
		if (x >= 0 && x <= 9) {
			return '0' + x;
		}
		else if (x >= 10 && x <= 16) {
			return 'A' + (x - 10);
		}
	}

	wchar_t hexifyw(int x) {
		if (x >= 0 && x <= 9) {
			return L'0' + x;
		}
		else if (x >= 10 && x <= 16) {
			return L'a' + (x - 10);
		}
	}

	BYTE RandomHex()
	{
		ULONG seed = KeQueryTimeIncrement();
		return hexify(RtlRandomEx(&seed) % 17);
	}

	BYTE RandomHexW()
	{
		ULONG seed = KeQueryTimeIncrement();
		return hexifyw(RtlRandomEx(&seed) % 17);
	}

	void GenerateMACAddress(BYTE* mac)
	{
		ULONG seed = KeQueryTimeIncrement();

		for (int i = 0; i < 32; i++)
			mac[i] = hexify(RtlRandomEx(&seed) % 17);

		mac[32] = '\0';
		char temp[] = { '2', '6', 'A', 'E' };
		mac[1] = temp[(RtlRandomEx(&seed) % 4)];
	}

	void RandomizeGUID(WCHAR* GUID)
	{
		for (int i = 0; i < 16; ++i)
		{
			BYTE random = RandomHexW();
			GUID[i] = random;
		}
	}

	void RandomizeSerialNumber(PCHAR serialNumber, UCHAR randomNumber)
	{
		int iIterator = 0;

		while (serialNumber[iIterator] != '\0')
		{
			UCHAR charCode = serialNumber[iIterator];

			if (charCode >= 48 && charCode <= 57)
			{
				UCHAR tempCode = charCode - 48;

				tempCode += randomNumber;

				while (tempCode > 9)
					tempCode -= 10;

				charCode = tempCode + 48;
			}

			if (charCode >= 97 && charCode <= 122)
			{
				UCHAR tempCode = charCode - 97;

				tempCode += randomNumber;

				while (tempCode > 25)
					tempCode -= 26;

				charCode = tempCode + 97;
			}

			if (charCode >= 65 && charCode <= 90)
			{
				UCHAR tempCode = charCode - 65;

				tempCode += randomNumber;

				while (tempCode > 25)
					tempCode -= 26;

				charCode = tempCode + 65;
			}

			serialNumber[iIterator] = charCode;

			iIterator++;
		}
	}

	NTSTATUS init_ldr_data()
	{
		UNICODE_STRING disk_driver_name = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
		PDRIVER_OBJECT disk_driver_object = nullptr;

		auto disk_status = ObReferenceObjectByName(&disk_driver_name, OBJ_CASE_INSENSITIVE, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, reinterpret_cast<PVOID*>(&disk_driver_object));

		if (disk_driver_object && NT_SUCCESS(disk_status))
		{
			disk_driver_name.Buffer = 0;
			PLDR_DATA_TABLE_ENTRY pThisModule = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(disk_driver_object->DriverSection);

			PLIST_ENTRY current_entry = pThisModule->InLoadOrderLinks.Flink;

			while (current_entry != &pThisModule->InLoadOrderLinks && current_entry != NULL)
			{
				PLDR_DATA_TABLE_ENTRY data_table_entry = CONTAINING_RECORD(current_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

				if (data_table_entry != nullptr && data_table_entry->BaseDllName.Length != 0 && !wcscmp(data_table_entry->BaseDllName.Buffer, L"ntoskrnl.exe"))
				{
					Globals::g_KernelBase = reinterpret_cast<uintptr_t>(data_table_entry->DllBase);
					Globals::g_KernelSize = reinterpret_cast<uintptr_t>(data_table_entry->SizeOfImage);
					Globals::g_PsLoadedModuleList = current_entry->Blink;
					ObDereferenceObject(disk_driver_object);
					return STATUS_SUCCESS;
				};
				current_entry = current_entry->Flink;
			};
		};
		return STATUS_FILE_NOT_AVAILABLE;
	};

	PDRIVER_OBJECT get_driver_object(PUNICODE_STRING DriverName)
	{
		PDRIVER_OBJECT DrvObject;
		if (NT_SUCCESS(ObReferenceObjectByName(DriverName, 0, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)& DrvObject)))
		{
			return DrvObject;
		}

		return NULL;
	}

	MODULEINFO get_system_module_info(const wchar_t* mod_name)
	{
		MODULEINFO ret = { 0 };

		if (mod_name == NULL || Globals::g_PsLoadedModuleList == NULL)
			return ret;

		if (IsListEmpty(Globals::g_PsLoadedModuleList))
			return ret;

		UNICODE_STRING unicode_mod_name;
		RtlInitUnicodeString(&unicode_mod_name, mod_name);

		for (auto current_entry = Globals::g_PsLoadedModuleList->Flink; current_entry != Globals::g_PsLoadedModuleList; current_entry = current_entry->Flink)
		{
			const auto data_table_entry = CONTAINING_RECORD(current_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (data_table_entry != nullptr && RtlEqualUnicodeString(&data_table_entry->BaseDllName, &unicode_mod_name, TRUE))
			{
				ret.lpBaseOfDll = data_table_entry->DllBase;
				ret.SizeOfImage = reinterpret_cast<int32_t>(data_table_entry->SizeOfImage);
				ret.EntryPoint = data_table_entry->EntryPoint;
				break;
			}
		}
		return ret;
	}

	MODULEINFO get_system_module_info(PVOID DriverSection)
	{
		const auto ldr_data = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(DriverSection);
		return get_system_module_info(ldr_data->BaseDllName.Buffer);
	}

	PVOID get_system_module(const wchar_t* mod_name)
	{
		return get_system_module_info(mod_name).lpBaseOfDll;
	}

	PVOID get_system_module(PVOID DriverSection)
	{
		const auto ldr_data = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(DriverSection);
		return get_system_module(ldr_data->BaseDllName.Buffer);
	}

#define INRANGE(x,a,b)    (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))

	bool CompareByteArray(unsigned char* pbBaseAddress, unsigned char* pbSignature, unsigned char* pbMask)
	{
		for (; *pbMask; ++pbMask, ++pbSignature, ++pbBaseAddress)
		{
			if (*pbMask == '\?')
				continue;

			if (*pbBaseAddress != *pbSignature)
				return false;
		};

		return true;
	};

	uintptr_t FindSignature(unsigned char* pBaseAddress, uintptr_t ui64ImageSize, unsigned char* pbSignature, unsigned char* pbMask)
	{
		unsigned char bFirstByte = pbSignature[0];
		unsigned char* pbProcessEnd = reinterpret_cast<unsigned char*>(reinterpret_cast<uintptr_t>(pBaseAddress) + (ui64ImageSize - static_cast<uintptr_t>(strlen(reinterpret_cast<const char*>(pbSignature)))));

		for (; pBaseAddress < pbProcessEnd; ++pBaseAddress)
		{
			if (*pBaseAddress != bFirstByte)
				continue;

			if (CompareByteArray(pBaseAddress, pbSignature, pbMask))
				return (reinterpret_cast<uintptr_t>(pBaseAddress));
		};

		return 0;
	};

	uintptr_t FindSignatureOffseted(unsigned char* pBaseAddress, uintptr_t ui64ImageSize, unsigned char* pbSignature, unsigned char* pbMask, long iOffsetPosition)
	{
		unsigned char bFirstByte = pbSignature[0];
		unsigned char* pbProcessEnd = reinterpret_cast<unsigned char*>(reinterpret_cast<uintptr_t>(pBaseAddress) + (ui64ImageSize - static_cast<uintptr_t>(strlen(reinterpret_cast<const char*>(pbSignature)))));

		for (; pBaseAddress < pbProcessEnd; ++pBaseAddress)
		{
			if (*pBaseAddress != bFirstByte)
				continue;

			if (CompareByteArray(pBaseAddress, pbSignature, pbMask))
			{
				uintptr_t ui64Address = reinterpret_cast<uintptr_t>(pBaseAddress);
				return ((ui64Address + (iOffsetPosition + 4) + *reinterpret_cast<long*>(ui64Address + iOffsetPosition)));
			};
		};

		return 0;
	};

	uintptr_t FindSignatureIDA(const char* szIDAStyle, unsigned char* pBaseAddress, uintptr_t ui64ImageSize, long iOffsetPosition)
	{
		int iIDAStyleLength = strlen(szIDAStyle);

		if (iIDAStyleLength <= 1)
			return 0;

		unsigned char* pbSignature = alloc_kernel_mem<unsigned char*>(iIDAStyleLength);
		memset(reinterpret_cast<void*>(pbSignature), 0, iIDAStyleLength);

		unsigned char* pbMask = alloc_kernel_mem<unsigned char*>(iIDAStyleLength);
		memset(reinterpret_cast<void*>(pbMask), 0, iIDAStyleLength);

		int iIterator = 0;
		while (*szIDAStyle != '\0')
		{
			if (*szIDAStyle == '?')
			{
				pbSignature[iIterator] = (unsigned char)'\x00';
				pbMask[iIterator] = (unsigned char)'\?';
			}
			else
			{
				pbSignature[iIterator] = (unsigned char)getByte(szIDAStyle);
				pbMask[iIterator] = (unsigned char)'x';
			};

			if (*(unsigned short*)szIDAStyle == '\?\?' || *szIDAStyle != '?')
			{
				if ((*(szIDAStyle + 1) == '\0') || (*(szIDAStyle + 2) == '\0'))
					break;

				szIDAStyle += 3;
			}
			else
			{
				if ((*(szIDAStyle + 1) == '\0'))
					break;

				szIDAStyle += 2;
			};

			iIterator++;
		};

		uintptr_t ui64Return;

		if (iOffsetPosition == 0x7FFFFFFF)
			ui64Return = FindSignature(pBaseAddress, ui64ImageSize, pbSignature, pbMask);
		else
			ui64Return = FindSignatureOffseted(pBaseAddress, ui64ImageSize, pbSignature, pbMask, iOffsetPosition);

		free_kernel_mem(pbSignature);
		free_kernel_mem(pbMask);

		return ui64Return;
	};
};