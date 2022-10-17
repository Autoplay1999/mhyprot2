#pragma once
#include <Windows.h>
#include <string>
#include <vector>

namespace mhyprot {
	bool Initialize();
	bool Install();
	void Uninstall();
	void SetProcessID(DWORD ProcessId);
	DWORD GetProcessID();
	bool ReadKernelMemory(DWORD64 Address, void* Buffer, DWORD Size);
	bool ReadProcessMemory(DWORD64 Address, void* Buffer, DWORD Size);
	bool WriteProcessMemory(DWORD64 Address, void* Buffer, DWORD Size);
	bool GetProcessModules(DWORD MaxCount, std::vector<std::pair<std::wstring, std::wstring>>& Result);

	template<class T> __forceinline T ReadKernelMemory(DWORD64 address) {
		T buffer;
		ReadKernelMemory(address, &buffer, sizeof(T));
		return buffer;
	}

	template<class T> __forceinline T ReadProcessMemory(DWORD64 address) {
		T buffer;
		ReadProcessMemory(address, &buffer, sizeof(T));
		return buffer;
	}
}
