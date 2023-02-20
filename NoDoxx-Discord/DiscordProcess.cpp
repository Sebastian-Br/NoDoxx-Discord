#include "DiscordProcess.h"
#include <fstream>
#include <iostream>
#include <boost/algorithm/string/find.hpp>

#if defined(_WIN32) || defined(_WIN64) 
#  include <string.h>
#  define strcasecmp _stricmp 
#  define strncasecmp _strnicmp 
#else
#  include <strings.h>
#endif

DiscordProcess::DiscordProcess(bool _print_debug_info)
{
	process_name = "Discord.exe";
    print_debug_info = _print_debug_info;
    ZeroMemory(nullwchars, sizeof(WCHAR) * 5000);
    forbidden_strings = std::list<std::string>();

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
    CloseHandles();
}

void DiscordProcess::CloseHandles()
{
    if (read_chat_msg_handle != NULL) {
        CloseHandle(read_chat_msg_handle);
    }

    if (read_chat_msg_length_handle != NULL) {
        CloseHandle(read_chat_msg_length_handle);
    }
}

bool DiscordProcess::LoadForbiddenStrings(std::string file_name)
{
    std::fstream file;
    file.open(file_name, std::ios::in);
    if (!file.is_open()) {
        if (print_debug_info) {
            std::cout << "DiscordProcess::LoadForbiddenStrings() Could not open " << file_name << std::endl;
        }
        return false;
    }

    std::string current_line;
    while (getline(file, current_line)) {
        forbidden_strings.push_back(current_line);
    }
    file.close();

    if (forbidden_strings.size() > 0) {
        return true;
    }

    if (print_debug_info) {
        std::cout << "DiscordProcess::LoadForbiddenStrings() File " << file_name << " contained no entries" << std::endl;
    }
    return false;
}

void DiscordProcess::DbgPrintForbiddenStrings()
{
    if (print_debug_info) {
        std::cout << "DiscordProcess::DbgPrintForbiddenStrings() Forbidden strings: \n";
        int i = 1;
        for (std::string s : forbidden_strings) {
            std::cout << "[" << i << "]: " << s << std::endl;
            i++;
        }
    }
}

bool DiscordProcess::Initialize()
{
    chat_msg_memory_address = chat_msg_memory_address_resolver.Resolve();
    if (chat_msg_memory_address == NULL) {
        if(print_debug_info)
            std::cout << "DiscordProcess::Initialize() chat_msg_memory_address_resolver.Resolve() returned NULL\n";
        return false;
    }
    else if (print_debug_info) {
        std::cout << std::hex << "chat_msg_memory_address_resolver.Resolve() returned " << chat_msg_memory_address << "\n";
    }

    chat_msg_length_memory_address = chat_msg_length_memory_address_resolver.Resolve();
    if (chat_msg_length_memory_address == NULL) {
        if (print_debug_info)
            std::cout << "DiscordProcess::Initialize() chat_msg_length_memory_address.Resolve() returned NULL\n";
        return false;
    }
    else if (print_debug_info) {
        std::cout << std::hex << "DiscordProcess::Initialize() chat_msg_length_memory_address.Resolve() returned " << chat_msg_length_memory_address << "\n";
    }

    read_chat_msg_handle = OpenProcess(PROCESS_ALL_ACCESS, false, chat_msg_memory_address_resolver.process_id);

    if (read_chat_msg_handle == NULL) {
        if (print_debug_info)
            std::cout << "DiscordProcess::Initialize(): read_chat_msg_handle was NULL / OpenProcess failed\n";
        return false;
    }
    else {
        std::cout << std::hex << "DiscordProcess::Initialize(): read_chat_msg_handle is " << read_chat_msg_handle << " / OpenProcess success!\n";
    }

    read_chat_msg_length_handle = OpenProcess(PROCESS_ALL_ACCESS, false, chat_msg_length_memory_address_resolver.process_id);

    if (read_chat_msg_length_handle == NULL) {
        if (print_debug_info)
            std::cout << "DiscordProcess::Initialize(): read_chat_msg_length_handle was NULL / OpenProcess failed\n";
        return false;
    }
    else {
        std::cout << std::hex << "DiscordProcess::Initialize(): read_chat_msg_length_handle is " << read_chat_msg_handle << " / OpenProcess success!\n";
    }

    return true;
}

std::string DiscordProcess::GetCurrentChatMsg()
{
    DWORD chat_msg_length = 0;
    DWORD chat_msg_length__bytes_read = 0;
    NTSTATUS chat_msg_length_read_ntstatus = NtReadVirtualMemory(read_chat_msg_length_handle, (PVOID) chat_msg_length_memory_address, &chat_msg_length, sizeof(chat_msg_length), &chat_msg_length__bytes_read);
    DWORD chat_msg_length_read__last_error = GetLastError();
    if (chat_msg_length_read_ntstatus != 0 || chat_msg_length__bytes_read != sizeof(chat_msg_length__bytes_read) || (chat_msg_length_read__last_error != 0 && chat_msg_length_read__last_error != 0x12)) {
        std::cout << std::hex << "DiscordProcess::GetCurrentChatMsg() Error. chat_msg_length_read_ntstatus = " << chat_msg_length_read_ntstatus << " | chat_msg_length__bytes_read = " << chat_msg_length__bytes_read << " |  chat_msg_length_read__last_error = " << chat_msg_length_read__last_error << "\n";
        std::cout << "DiscordProcess::GetCurrentChatMsg() Read value: chat_msg_length = " << chat_msg_length << "\n";
        return NULL;
    }
    else if (print_debug_info) {
        std::cout << "DiscordProcess::GetCurrentChatMsg() chat_msg_length = " << chat_msg_length << "\n";
    }

    const int MAX_CHAT_MSG_LENGTH = 5000;
    WCHAR chat_msg_wchars[MAX_CHAT_MSG_LENGTH];
    ZeroMemory(chat_msg_wchars, MAX_CHAT_MSG_LENGTH * sizeof(WCHAR));
    DWORD chat_msg__bytes_read = 0;
    if (chat_msg_length > MAX_CHAT_MSG_LENGTH) {
        chat_msg_length = MAX_CHAT_MSG_LENGTH;
    }

    NTSTATUS chat_msg_read_ntstatus = NtReadVirtualMemory(read_chat_msg_handle, (PVOID)chat_msg_memory_address, &chat_msg_wchars, chat_msg_length * sizeof(WCHAR), &chat_msg__bytes_read);
    DWORD chat_msg_read__last_error = GetLastError();
    if (chat_msg_read_ntstatus != 0 || chat_msg__bytes_read != sizeof(WCHAR) * chat_msg_length || (chat_msg_read__last_error != 0 && chat_msg_read__last_error != 0x12) || (int) chat_msg_wchars[MAX_CHAT_MSG_LENGTH-1] != 0) {
        std::cout << "DiscordProcess::GetCurrentChatMsg() Error. chat_msg_read_ntstatus = " << chat_msg_read_ntstatus << " | chat_msg__bytes_read = " << chat_msg__bytes_read << " |  chat_msg_read__last_error = " << chat_msg_read__last_error << "\n";
        return NULL;
    }
    else if (print_debug_info) {
        std::cout << "DiscordProcess::GetCurrentChatMsg() excluding ', chat_msg[] = '";
        wprintf(chat_msg_wchars);
        std::cout << "'";
        std::cout << "\n";
    }

    std::wstring chat_msg_wstring(chat_msg_wchars);
    std::string result(chat_msg_wstring.begin(), chat_msg_wstring.end());
    return result;
}

unsigned int DiscordProcess::TestCurrentChatMsg()
{
    std::string current_chat_msg = GetCurrentChatMsg();

    for (std::string current_forbidden_string : forbidden_strings) {
        boost::iterator_range<std::string::const_iterator> boost_iter_find_substring; // ok maybe using-statements would be a good idea.
        boost_iter_find_substring = boost::ifind_first(current_chat_msg, current_forbidden_string);
        std::string::const_iterator iter_begin = boost_iter_find_substring.begin();
        std::string::const_iterator iter_end = boost_iter_find_substring.end();

        if (iter_begin != iter_end) { // if they are the same, the substring is not found in the string
            SuspendProcess(chat_msg_memory_address_resolver.process_id, true);
            DWORD local_address_of__current_chat_msg = ((DWORD)&current_chat_msg); // grabs the least significant DWORD from the QWORD memory address (x64) of the current chat message string
            DWORD dw_iter_begin = *(DWORD*)&iter_begin; // iterators are just pointers. all this does is convert the pointer to a DWORD.
            DWORD substring_position = dw_iter_begin - local_address_of__current_chat_msg; // the difference of the pointers equals the position of where the substring was found because 1 char in each string is 1 byte
            //std::cout << "Iterator: " << dw_iter_begin << " local_address_of__current_chat_msg: " << local_address_of__current_chat_msg << std::endl;
            //std::cout << "dw_position: " << dw_position << std::endl;
            std::cout << "DiscordProcess::TestCurrentChatMsg() '" << current_forbidden_string << "' is in the message @position: " << substring_position << std::endl;
            OverwriteChatMessage(substring_position + current_forbidden_string.length()); // this is currently overwriting text at the wrong address
            TerminateProcess(read_chat_msg_handle, 0xff); // just terminate the process to prevent the msg from being sent. in the future, the memory should be overwritten.
            CloseHandles();
            return 1;
            SuspendProcess(chat_msg_memory_address_resolver.process_id, false);
        }
        else {
            if (print_debug_info) {
                std::cout << "DiscordProcess::TestCurrentChatMsg() String not found!\n";
            }
        }
    }

    return 0;
}

bool DiscordProcess::OverwriteChatMessage(DWORD offsetpluslength)
{
    size_t numberofbyteswritten_chatmsg = 0; // overwrites the chat msg memory [address] with null bytes
    if (WriteProcessMemory(read_chat_msg_handle, (LPVOID)chat_msg_memory_address, nullwchars, sizeof(WCHAR) * offsetpluslength, &numberofbyteswritten_chatmsg)) {
        if (print_debug_info) {
            std::cout << std::dec << "WriteProcessMemory(read_chat_msg_handle,...) success! Number of bytes written: " << numberofbyteswritten_chatmsg << "\n";
        }
    }
    else {
        std::cout << "WriteProcessMemory(read_chat_msg_handle,...) failed!\n";
        return false;
    }

    DWORD dwone = 1; // writes 1 to the memory address where the chat message length is stored
    size_t numberofbyteswritten_chatmsglength = 0;
    if (WriteProcessMemory(read_chat_msg_length_handle, (LPVOID)chat_msg_length_memory_address, &dwone, sizeof(DWORD), & numberofbyteswritten_chatmsglength)) {
        if (print_debug_info) {
            std::cout << std::dec << "WriteProcessMemory(read_chat_msg_length_handle,...) success! Number of bytes written: " << numberofbyteswritten_chatmsglength << "\n";
        }
    }
    else {
        std::cout << "WriteProcessMemory(read_chat_msg_length_handle,...) failed!\n";
        return false;
    }

    return true;
}

void DiscordProcess::SuspendProcess(DWORD ProcessId, bool Suspend)
{
    HANDLE all_threads_handle = NULL;
    THREADENTRY32 thread = { 0 };
    thread.dwSize = sizeof(THREADENTRY32);

    all_threads_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (all_threads_handle == INVALID_HANDLE_VALUE)
        return;

    if (Thread32First(all_threads_handle, &thread))
    {
        do
        {
            if (thread.th32OwnerProcessID == ProcessId)
            {
                HANDLE handle_current_thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread.th32ThreadID); // handle to the current thread in the threadlist (not the current thread of execution)
                if (handle_current_thread != NULL) {
                    if (Suspend == false)
                    {
                        ResumeThread(handle_current_thread);
                    }
                    else
                    {
                        SuspendThread(handle_current_thread);
                    }

                    CloseHandle(handle_current_thread);
                }
            }
        } while (Thread32Next(all_threads_handle, &thread));
    }
    CloseHandle(all_threads_handle);
}