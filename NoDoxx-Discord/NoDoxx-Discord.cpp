#include <iostream>

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>

#include "MemoryAddressResolver.h"
#include "DiscordProcess.h"

using namespace std;

void JustWait() {
    while (true) {
        Sleep(1000);
    }
}

int main()
{
    bool print_dbg_info = false;
    cout << "application started\n";
    DiscordProcess discord_process = DiscordProcess(print_dbg_info);

    while (!discord_process.LoadForbiddenStrings("forbidden_strings.txt")) {
        Sleep(2000);
    }

    discord_process.DbgPrintForbiddenStrings();

    location_pre_initialization:
    while (!discord_process.Initialize()) {
        cout << "Waiting to find the process...\n";
        Sleep(1000);
    }

    cout << "Initialization successful!" << endl;

    while (true) { // replace with code that checks if the process is still the same/handles are valid
        if (discord_process.TestCurrentChatMsg() > 0) {
            cout << "Process Terminated!";
            goto location_pre_initialization;
        }
        Sleep(100);
    }

    cout << "Execution terminated\n";
}