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
	/// <summary>
	/// Constructs the class and sets the process name and initializes MemoryAddressResolvers.
	/// </summary>
	/// <param name="_print_debug_info">Whether (true) or not (false) to print debugging information</param>
	DiscordProcess(bool _print_debug_info);

	/// <summary>
	/// Frees resources (handles) associated with an instance by calling CloseHandles() when the instance goes out of scope.
	/// </summary>
	~DiscordProcess();

	/// <summary>
	/// Closes the process handles associated with the instance.
	/// </summary>
	void CloseHandles();

	/// <summary>
	/// Loads a list of strings from a file.
	/// If the chat message in the discord-window contains one of these strings, the process is killed.
	/// File format: 1 string per line (newline is the separator)
	/// </summary>
	/// <param name="file_name">The file from which to read strings line by line</param>
	/// <returns>True: The file exists and more than 1 entry has been read. False otherwise.</returns>
	bool LoadForbiddenStrings(std::string file_name);

	/// <summary>
	/// Prints the strings described in LoadForbiddenStrings()
	/// </summary>
	void DbgPrintForbiddenStrings();

	/// <summary>
	/// Resolves the memory addresses and obtains handle(s) for Discord.exe process(es).
	/// </summary>
	/// <returns>True if all that succeeds, false otherwise.</returns>
	bool Initialize();

	/// <summary>
	/// Reads the address in the virtual memory of the Discord-process where the chat-message resides.
	/// This unfortunately is not the address where this data is ultimately stored and it seems that this address is used for display/other purposes.
	/// I wasn't yet able to find the code that writes to this address to identify where in memory the 'actual' data is held.
	/// </summary>
	/// <returns>The string (converted from wchars to a wstring to a string) of the correct length (which is also read from a memory address)</returns>
	std::string GetCurrentChatMsg();

	/// <summary>
	/// Tests if the chat message which the user is currently typing contains any of the forbidden strings.
	/// </summary>
	/// <returns>0 if the chat message does not contain any of the forbidden strings. Nonzero otherwise.</returns>
	unsigned int TestCurrentChatMsg();

	/// <summary>
	/// Overwrites the chat message (not yet the correct address though!) in the VA-space of the discord process and the address where its length is stored (this likewise is used only for display-purposes and does not represent the 'backend'-logic).
	/// Everything up until and including the chat message is nulled.
	/// </summary>
	/// <param name="offsetpluslength">The sum of the offset to the first character of the substring-to-be-deleted and the length of that substring</param>
	/// <returns>True: The write operation is successful. False otherwise.</returns>
	bool OverwriteChatMessage(DWORD offsetpluslength);

	/// <summary>
	/// Suspends (or resumes) a process by suspending all its threads.
	/// In this class, this function is only used to suspend the Discord-process.
	/// </summary>
	/// <param name="ProcessId">The process-ID.</param>
	/// <param name="Suspend">True: Suspends the process. False: Resumes the process.</param>
	void SuspendProcess(DWORD ProcessId, bool Suspend);

	/// <summary>
	/// The list of strings that we do not want Discord to send
	/// </summary>
	std::list<std::string> forbidden_strings;

	/// <summary>
	/// The name of the process, "Discord.exe"
	/// </summary>
	std::string process_name;

	// The memory address resolvers used to resolve the address of the chat message and its length. ASLR necessitates this.
	MemoryAddressResolver chat_msg_memory_address_resolver;
	MemoryAddressResolver chat_msg_length_memory_address_resolver;

	// When the addresses are resolved, the results are written to these variables.
	DWORD chat_msg_memory_address; // Discord.exe+06D636E8 -> 28 -> 1AC -> 8C -> 0
	DWORD chat_msg_length_memory_address; // Discord.exe+06D34A78 -> 8F0 -> C -> 28 -> 14 -> 44 -> 1CC -> 4C

	// The handles to the processes that contain the chat message/chat message length respectively.
	HANDLE read_chat_msg_handle;
	HANDLE read_chat_msg_length_handle; // in case that some values are not contained in the same process

	/// <summary>
	/// An array of 5000 null-wchars.
	/// </summary>
	WCHAR nullwchars[5000];

	/// <summary>
	/// Whether (true) or not (false) to print debug information.
	/// </summary>
	bool print_debug_info;
};

//ChatMsg, first~80? characters@ textinputframework.dll+AB730 <-- outdated as of Feb 19th 2023