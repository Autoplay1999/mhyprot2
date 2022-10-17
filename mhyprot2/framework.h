#pragma once
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Advapi32.lib")

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include "phnt/phnt_windows.h"
#include "phnt/phnt.h"

#include <assert.h>
#include <memory>
#include <string>
#include <format>
#include <fstream>
#include <filesystem>
#include <vector>

#include "xorstr.h"

using namespace std;