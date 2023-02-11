#pragma once
#include <string>
#include <list>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <vector>
class MemoryAddressResolver
{
private:
	/// <summary>
	/// For a specific process-id, retrieves the base address of the module with the name module_name.
	/// This function is called by GetModuleBaseAddress() because 
	/// </summary>
	/// <param name="processID"></param>
	/// <returns></returns>
	DWORD GetBaseAddressOfModuleInProcess(DWORD processID);

	/// <summary>
	/// Gets the process IDs of all processes of the same process_name.
	/// </summary>
	/// <returns></returns>
	std::list<int> GetProcessIDs();

	/// <summary>
	/// This function is called internally after the process and module name have been set in the constructor.
	/// </summary>
	/// <returns>The base address of the module module_name</returns>
	DWORD GetModuleBaseAddress();
public:

	MemoryAddressResolver(); //do not use this constructor
	MemoryAddressResolver(std::string _process_name);
	MemoryAddressResolver(std::string _process_name, std::string _module_name);
	void AddOffset(unsigned int offset);

	

	/// <summary>
	/// Retrieves the base address of module, then adds the first offset to it and reads the value at that memory address.
	/// For each subsequent offset, adds the offset to that value and reads/dereferences the memory at [value+offset].
	/// Repeats this process until all offsets have been navigated.
	/// </summary>
	/// <returns>The address at the end of the pointer cascade. Returns NULL on failure.</returns>
	DWORD Resolve();

	std::string process_name;
	DWORD process_id;
	std::string module_name;
	DWORD module_base_address;
	std::list<unsigned int> offsets;

	int nth_process;
};