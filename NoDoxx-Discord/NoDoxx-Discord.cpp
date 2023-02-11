#include <iostream>

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>

#include "MemoryAddressResolver.h"
#include "DiscordProcess.h"

using namespace std;


int main()
{
    bool print_dbg_info = true;
    cout << "application started\n";

    DiscordProcess discord_process = DiscordProcess(print_dbg_info);
    if (discord_process.Initialize()) {
        cout << "Initialization successful!" << endl;
    }
    else {
        cout << "Initialization failed!" << endl;
        return 0xff;
    }

    discord_process.GetCurrentChatMsg();
    
    cout << "Execution terminated\n";
}