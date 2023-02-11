#pragma once
#include <string>
#include <windows.h>
#include <iostream>
#include <winternl.h>

#include "MemoryAddressResolver.h"

#pragma comment (lib, "ntdll.lib")
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);

class DiscordProcess
{
public:
	DiscordProcess(bool _print_debug_info);
	~DiscordProcess();
	bool Initialize();
	void GetCurrentChatMsg();
	std::string process_name;

	MemoryAddressResolver chat_msg_memory_address_resolver;
	MemoryAddressResolver chat_msg_length_memory_address_resolver;

	DWORD chat_msg_memory_address; // Discord.exe+06D636E8 -> 28 -> 1AC -> 8C -> 0
	DWORD chat_msg_length_memory_address; // Discord.exe+06D34A78 -> 8F0 -> C -> 28 -> 14 -> 44 -> 1CC -> 4C

	HANDLE read_chat_msg_handle;
	HANDLE read_chat_msg_length_handle; // in case that some values are not contained in the same process

	bool print_debug_info;
};

//ChatMsg, first~80? characters@ textinputframework.dll+AB730