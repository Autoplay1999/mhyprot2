#include <Windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <TlHelp32.h>
#include "mhyprot.hpp"

using namespace std;

DWORD GetProcessIDByName(const wstring& ProcessName) {
    DWORD processId{};
    auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (!hSnapshot)
        return processId;

    PROCESSENTRY32 procEntry{sizeof(PROCESSENTRY32)};

    if (!Process32First(hSnapshot, &procEntry))
        return processId;

    do {
        if (_wcsicmp(procEntry.szExeFile, ProcessName.c_str()) != 0)
            continue;

        processId = procEntry.th32ProcessID;
        break;
    } while (Process32Next(hSnapshot, &procEntry));

    return processId;
}

int main() {
    if (!mhyprot::Install())
        return 1;

    if (!mhyprot::Initialize())
        return 2;

    DWORD procId;

    while (!(procId = GetProcessIDByName(L"CabalMain.exe")))
        this_thread::sleep_for(chrono::milliseconds(100));

    auto result = mhyprot::ReadProcessMemory<DWORD>(0x400000);

    printf("%08X\n", result);

    // mhyprot::Uninstall();
}