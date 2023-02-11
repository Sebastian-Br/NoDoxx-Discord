#include "DiscordProcess.h"

DiscordProcess::DiscordProcess(bool _print_debug_info)
{
	process_name = "Discord.exe";
    print_debug_info = _print_debug_info;

    chat_msg_memory_address_resolver = MemoryAddressResolver(process_name);
    chat_msg_memory_address_resolver.nth_process = 1;
    chat_msg_memory_address_resolver.AddOffset(0x06D636E8); //Discord.exe + 06D636E8 -> 28 -> 1AC -> 8C -> 0
    chat_msg_memory_address_resolver.AddOffset(0x28);
    chat_msg_memory_address_resolver.AddOffset(0x1AC);
    chat_msg_memory_address_resolver.AddOffset(0x8C);
    chat_msg_memory_address_resolver.AddOffset(0x0);

    chat_msg_length_memory_address_resolver = MemoryAddressResolver(process_name); // Discord.exe+06D34A78 -> 8F0 -> C -> 28 -> 14 -> 44 -> 1CC -> 4C
    chat_msg_length_memory_address_resolver.nth_process = 1;
    chat_msg_length_memory_address_resolver.AddOffset(0x06D34A78);
    chat_msg_length_memory_address_resolver.AddOffset(0x8F0);
    chat_msg_length_memory_address_resolver.AddOffset(0xC);
    chat_msg_length_memory_address_resolver.AddOffset(0x28);
    chat_msg_length_memory_address_resolver.AddOffset(0x14);
    chat_msg_length_memory_address_resolver.AddOffset(0x44);
    chat_msg_length_memory_address_resolver.AddOffset(0x1CC);
    chat_msg_length_memory_address_resolver.AddOffset(0x4C);
}

DiscordProcess::~DiscordProcess()
{
    if (read_chat_msg_handle != NULL) {
        CloseHandle(read_chat_msg_handle);
    }
}

bool DiscordProcess::Initialize()
{
    chat_msg_memory_address = chat_msg_memory_address_resolver.Resolve();
    if (chat_msg_memory_address == NULL) {
        std::cout << "DiscordProcess::Initialize(): chat_msg_memory_address_resolver.Resolve() returned NULL\n";
        return false;
    }
    else if (print_debug_info) {
        std::cout << std::hex << "chat_msg_memory_address_resolver.Resolve() returned " << chat_msg_memory_address << "\n";
    }

    chat_msg_length_memory_address = chat_msg_length_memory_address_resolver.Resolve();
    if (chat_msg_length_memory_address == NULL) {
        std::cout << "DiscordProcess::Initialize(): chat_msg_length_memory_address.Resolve() returned NULL\n";
        return false;
    }
    else if (print_debug_info) {
        std::cout << std::hex << "chat_msg_length_memory_address.Resolve() returned " << chat_msg_length_memory_address << "\n";
    }

    read_chat_msg_handle = OpenProcess(PROCESS_VM_READ, false, chat_msg_memory_address_resolver.process_id);

    if (read_chat_msg_handle == NULL) {
        std::cout << "DiscordProcess::Initialize(): read_chat_msg_handle was NULL / OpenProcess failed\n";
        return false;
    }
    else {
        std::cout << std::hex << "DiscordProcess::Initialize(): read_chat_msg_handle is " << read_chat_msg_handle << " / OpenProcess success!\n";
    }

    read_chat_msg_length_handle = OpenProcess(PROCESS_VM_READ, false, chat_msg_length_memory_address_resolver.process_id);

    if (read_chat_msg_length_handle == NULL) {
        std::cout << "DiscordProcess::Initialize(): read_chat_msg_length_handle was NULL / OpenProcess failed\n";
        return false;
    }
    else {
        std::cout << std::hex << "DiscordProcess::Initialize(): read_chat_msg_length_handle is " << read_chat_msg_handle << " / OpenProcess success!\n";
    }

    return true;
}

void DiscordProcess::GetCurrentChatMsg()
{
    DWORD chat_msg_length = 0;
    DWORD chat_msg_length__bytes_read = 0;
    NTSTATUS chat_msg_length_read_ntstatus = NtReadVirtualMemory(read_chat_msg_length_handle, (PVOID) chat_msg_length_memory_address, &chat_msg_length, sizeof(chat_msg_length), &chat_msg_length__bytes_read);
    DWORD chat_msg_length_read__last_error = GetLastError();
    if (chat_msg_length_read_ntstatus != 0 || chat_msg_length__bytes_read != sizeof(chat_msg_length__bytes_read) || (chat_msg_length_read__last_error != 0 && chat_msg_length_read__last_error != 0x12)) {
        std::cout << std::hex << "DiscordProcess::GetCurrentChatMsg() Error. chat_msg_length_read_ntstatus = " << chat_msg_length_read_ntstatus << " | chat_msg_length__bytes_read = " << chat_msg_length__bytes_read << " |  chat_msg_length_read__last_error = " << chat_msg_length_read__last_error << "\n";
        std::cout << "Read value: chat_msg_length = " << chat_msg_length << "\n";
        return;
    }
    else if (print_debug_info) {
        std::cout << "DiscordProcess::GetCurrentChatMsg() chat_msg_length = " << chat_msg_length << "\n";
    }

    WCHAR chat_msg[5000];
    ZeroMemory(chat_msg, 5000 * sizeof(WCHAR));
    DWORD chat_msg__bytes_read = 0;
    NTSTATUS chat_msg_read_ntstatus = NtReadVirtualMemory(read_chat_msg_handle, (PVOID)chat_msg_memory_address, &chat_msg, chat_msg_length * sizeof(WCHAR), &chat_msg__bytes_read);
    DWORD chat_msg_read__last_error = GetLastError();
    if (chat_msg_read_ntstatus != 0 || chat_msg__bytes_read != sizeof(WCHAR) * chat_msg_length || (chat_msg_read__last_error != 0 && chat_msg_read__last_error != 0x12)) {
        std::cout << "DiscordProcess::GetCurrentChatMsg() Error. chat_msg_read_ntstatus = " << chat_msg_read_ntstatus << " | chat_msg__bytes_read = " << chat_msg__bytes_read << " |  chat_msg_read__last_error = " << chat_msg_read__last_error << "\n";
        return;
    }
    else if (print_debug_info) {
        std::cout << "DiscordProcess::GetCurrentChatMsg() excluding ', chat_msg[] = '";
        wprintf(chat_msg);
        std::cout << "'";
        std::cout << "\n";
    }
}