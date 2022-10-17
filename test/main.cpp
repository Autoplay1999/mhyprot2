#include <Windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <deque>
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

    while (!(procId = GetProcessIDByName(L"csrss.exe")))
        this_thread::sleep_for(chrono::milliseconds(100));

    deque<mhyprot::ModuleInfo> mods;
    deque<mhyprot::ThreadInfo> threads;

    mhyprot::SetProcessID(procId);
    
    if (mhyprot::GetProcessModules(mods)) {
        cout << "[Modules]" << endl;

        for (auto& mod : mods)
            wcout << format(L"{:<32} {}", mod.ImageName, mod.FileName) << endl;

        cout << endl;
    }

    if (mhyprot::GetProcessThreads(threads)) {
        cout << "[Thread]" << endl;

        for (auto& thread : threads)
            wcout << format(L"{:016X} {:016X}", thread.KernelAddress, thread.StartAddress) << endl;

        cout << endl;
    }

    mhyprot::Uninstall();
}