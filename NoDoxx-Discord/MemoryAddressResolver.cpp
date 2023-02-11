#include "MemoryAddressResolver.h"
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <iostream>

using namespace std;

DWORD MemoryAddressResolver::GetModuleBaseAddress() // see: https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
{
	list<int> dwPIDs = GetProcessIDs(); // produces a weird error when DWORD is used as the template type
	if (dwPIDs.size() == 0)
	{
		_tprintf(TEXT("GetModuleBaseAddress(): Process not found!")); // _tprintf(TEXT(""));
		return 0;
	}

	std::cout << "GetModuleBaseAddress(): Nr of processes found: " << dwPIDs.size() << endl;

	int current_nth_process = 0;
	for (DWORD dwPID : dwPIDs) {
		current_nth_process++;
		if (current_nth_process == nth_process) {
			DWORD result = GetBaseAddressOfModuleInProcess(dwPID);
			if (result != 0) {
				process_id = dwPID;
				return result;
			}
		}
	}

	_tprintf(TEXT("GetModuleBaseAddress(): Module Base Address not found!"));
	return 0;
}

list<int> MemoryAddressResolver::GetProcessIDs()
{
	list<int> results = list<int>();
	HANDLE hSnapshot;
	PROCESSENTRY32 pe;
	BOOL hResult;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) return results;

	pe.dwSize = sizeof(PROCESSENTRY32);

	hResult = Process32First(hSnapshot, &pe);
	
	while (hResult) {
		wstring tmp_process_name_wstring = wstring(process_name.begin(), process_name.end());
		const wchar_t* tmp_process_name_wchar = tmp_process_name_wstring.c_str();
		if (wcscmp(tmp_process_name_wchar, pe.szExeFile) == 0) {
			results.push_back(pe.th32ProcessID);
		}
		hResult = Process32Next(hSnapshot, &pe);
	}

	CloseHandle(hSnapshot);
	return results;
}

DWORD MemoryAddressResolver::GetBaseAddressOfModuleInProcess(DWORD processID)
{
	HMODULE modules[1024];
	HANDLE process_handle;
	DWORD bytes_needed;

	printf("\nGetBaseAddressOfModuleInProcess() Process ID: %u\n", processID);

	// Get a handle to the process.
	process_handle = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (NULL == process_handle)
		return 1;

	// Get a list of all the modules in this process and save it to modules
	if (EnumProcessModulesEx(process_handle, modules, sizeof(modules), &bytes_needed, LIST_MODULES_ALL))
	{
		for (int i = 0; i < (bytes_needed / sizeof(HMODULE)); i++)
		{
			WCHAR current_module_name[MAX_PATH];

			// Write the module name to tmp_module_name
			if (GetModuleBaseNameW(process_handle, modules[i], current_module_name,
				sizeof(current_module_name) / sizeof(WCHAR)))
			{
				wstring targetmodulename_wstring(module_name.begin(), module_name.end()); // this is the module name we're looking for
				const wchar_t* targetmodulename_wchars = targetmodulename_wstring.c_str();
				if (wcscmp(targetmodulename_wchars, current_module_name) == 0) {
					// Print the module name and handle value.
					_tprintf(TEXT("\t%s (0x%08X)\n"), current_module_name, modules[i]);
					CloseHandle(process_handle);
					return (DWORD) modules[i];
				}
			}
		}
	}

	// Release the handle to the process.
	CloseHandle(process_handle);

	return 0;
}


MemoryAddressResolver::MemoryAddressResolver()
{
}

/// <summary>
/// Use this constructor when the process executable is also the module your offsets refer to
/// </summary>
/// <param name="_process_name">The name of the process</param>
MemoryAddressResolver::MemoryAddressResolver(std::string _process_name)
{
	module_base_address = NULL;
	offsets = std::list<unsigned int>();
	process_name = _process_name;
	process_id = 0;
	module_name = process_name;
	nth_process = 1;
}

MemoryAddressResolver::MemoryAddressResolver(std::string _process_name, std::string _module_name)
{
	module_base_address = NULL;
	offsets = std::list<unsigned int>();
	process_name = _process_name;
	process_id = 0;
	module_name = _module_name;
	nth_process = 1;
}

void MemoryAddressResolver::AddOffset(unsigned int offset)
{
	offsets.push_back(offset);
}

DWORD MemoryAddressResolver::Resolve()
{
	module_base_address = GetModuleBaseAddress();
	if (module_base_address == NULL) {
		return 0;
	}

	DWORD current_address = module_base_address;
	HANDLE process_handle = OpenProcess(PROCESS_VM_READ, false, process_id);
	if (process_handle == NULL) {
		return 0;
	}

	DWORD read_dword = 0;
	int read_address = 0;
	for (unsigned int current_offset : offsets) {
		read_address = current_address + current_offset;
		size_t bytes_read = 0;
		ReadProcessMemory(process_handle, (LPCVOID)read_address, &read_dword, sizeof(read_dword), &bytes_read);
		if (bytes_read != 4) {
			cout << "Resolve(): [ERROR] bytes_read != 4";
			CloseHandle(process_handle);
			return 0;
		}

		if (read_dword == NULL) {
			cout << "Resolve(): [ERROR] read_dword == NULL";
			CloseHandle(process_handle);
			return 0;
		}

		cout << hex << "current_address: " << current_address << " current_offset: " << current_offset << " read_address: " << read_address << " value at that address: " << read_dword << endl;
		current_address = read_dword;
	}

	CloseHandle(process_handle);
	return read_address;
}