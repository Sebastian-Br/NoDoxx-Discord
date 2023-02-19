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

	MemoryAddressResolver(); //do not use this constructor - it only exists to prevent a compilation error
	/// <summary>
	/// Using this constructor, the process name and module name are the same.
	/// If there exist multiple processes with the same name, the nth=1 process is believed to be the one you're interested in.
	/// </summary>
	/// <param name="_process_name">The name of the process. This process must also be the module you're interested in.</param>
	MemoryAddressResolver(std::string _process_name);

	/// <summary>
	/// Using this constructor, the process name and module name can be specified separately, e.g. "Discord.exe" and "textinputframework.dll"
	/// If there exist multiple processes with the same name, the nth=1 process is believed to be the one you're interested in.
	/// </summary>
	/// <param name="_process_name">The name of the process in whose address space the module resides.</param>
	/// <param name="_module_name">The name of the module that this process loaded containing the data you're interested in.</param>
	MemoryAddressResolver(std::string _process_name, std::string _module_name);

	/// <summary>
	/// Adds an offset to the list of offsets.
	/// When using CE, add the offsets starting from the very bottom upwards.
	/// </summary>
	/// <param name="offset">The offset to be added</param>
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

	/// <summary>
	/// If this is 1, the first process will be chosen if there are different processes that share the same name
	/// </summary>
	int nth_process;
};