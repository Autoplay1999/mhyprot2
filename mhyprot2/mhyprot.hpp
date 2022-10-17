#pragma once
#include <Windows.h>
#include <string>
#include <deque>

namespace mhyprot {
	struct ThreadInfo {
		DWORD64 KernelAddress;
		DWORD64 StartAddress;
	};

	struct ModuleInfo {
		std::wstring ImageName;
		std::wstring FileName;
	};

	bool Initialize();
	bool Install();
	void Uninstall();
	void SetProcessID(DWORD ProcessId);
	DWORD GetProcessID();
	bool ReadKernelMemory(DWORD64 Address, void* Buffer, DWORD Size);
	bool ReadProcessMemory(DWORD64 Address, void* Buffer, DWORD Size);
	bool WriteProcessMemory(DWORD64 Address, void* Buffer, DWORD Size);
	bool GetProcessModules(std::deque<ModuleInfo>& Result);
	bool GetProcessThreads(std::deque<ThreadInfo>& result);
	DWORD GetSystemUptime();
	bool TerminateProcess();

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
