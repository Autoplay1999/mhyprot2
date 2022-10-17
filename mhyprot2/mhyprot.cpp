#include "pch.h"
#include "mhyprot.hpp"
#include "raw_driver.hpp"

#define SERVICE_NAME xorstr_("mhyprot2")
#define SERVICE_PATH xorstr_("5eef18bf-ce3d-4443-9528-09919afa348e")
#define SERVICE_DIR	xorstr_("Temp")
#define SERVICE_FILE xorstr_("mhyprot2.sys")
#define DEVICE_NAME xorstr_(R"(\\.\mhyprot2)")
#define MODULE_NAME	xorstr_("mhyprot")
#define SYSFILE_NAME xorstr_("mhyprot.sys")

#define MHYPROT_IOCTL_INITIALIZE                0x80034000
#define MHYPROT_IOCTL_READ_KERNEL_MEMORY        0x83064000
#define MHYPROT_IOCTL_READ_WRITE_USER_MEMORY    0x81074000
#define MHYPROT_IOCTL_ENUM_PROCESS_MODULES      0x82054000
#define MHYPROT_IOCTL_GET_SYSTEM_UPTIME         0x80134000
#define MHYPROT_IOCTL_ENUM_PROCESS_THREADS      0x83024000
#define MHYPROT_IOCTL_TERMINATE_PROCESS         0x81034000

#define MHYPROT_OFFSET_SEEDMAP 0xA0E8

#define MHYPROT_ACTION_READ  0x0
#define MHYPROT_ACTION_WRITE 0x1

#define MHYPROT_ENUM_PROCESS_MODULE_SIZE 0x3A0
#define MHYPROT_ENUM_PROCESS_THREADS_SIZE 0xA8
#define MHYPROT_ENUM_PROCESS_THREADS_CODE 0x88

#define CHECK_HANDLE(x) (x && x != INVALID_HANDLE_VALUE)
#define MIN_ADDRESS ((ULONG_PTR)0x8000000000000000)

#ifdef _DEBUG
#	define THROW_WINAPI_(name, msg, result) throw exception(vformat(__FUNCTION__ " => " name " = " msg " ({:08X})", make_format_args(result)).c_str())
#	define THROW_WINAPI(name, msg)          throw exception(vformat(__FUNCTION__ " => " name " = " msg " ({:08X})", make_format_args(GetLastError())).c_str())
#	define THROW_NTAPI(name, result)        throw exception(vformat(__FUNCTION__ " => " name " = {:08X}", make_format_args(result)).c_str())
#	define THROW_USER(name, msg)            throw exception(__FUNCTION__ " => " name " = msg")
#else
#	define THROW_WINAPI_(name, msg, result) throw exception()
#	define THROW_WINAPI(name, msg)          throw exception()
#	define THROW_NTAPI(name, result)        throw exception()
#	define THROW_USER(name, msg)            throw exception()
#endif

#undef CreateService





static bool DriverIsExist();
static bool DriverIsStart();
static void DriverStart();
static void DriverStop();
static void DriverDelete();
static void DriverCreate();





struct Mhyprot {
	Mhyprot();
	~Mhyprot();

	static void CreateInstance();
};

typedef struct _MHYPROT_INITIALIZE {
	DWORD		_m_001;
	DWORD		_m_002;
	DWORD64		_m_003;
} MHYPROT_INITIALIZE, * PMHYPROT_INITIALIZE;

typedef struct _MHYPROT_KERNEL_READ_REQUEST {
	DWORD64		address;
	ULONG		size;
} MHYPROT_KERNEL_READ_REQUEST, * PMHYPROT_KERNEL_READ_REQUEST;

typedef struct _MHYPROT_USER_READ_WRITE_REQUEST {
	DWORD64		response;
	DWORD		action_code;
	DWORD		reserved_01;
	DWORD		process_id;
	DWORD		reserved_02;
	DWORD64		buffer;
	DWORD64		address;
	ULONG		size;
	ULONG		reverved_03;
} MHYPROT_USER_READ_WRITE_REQUEST, * PMHYPROT_USER_READ_WRITE_REQUEST;

typedef struct _MHYPROT_ENUM_PROCESS_THREADS_REQUEST {
	DWORD validation_code;
	DWORD process_id;
	DWORD owner_process_id;
} MHYPROT_ENUM_PROCESS_THREADS_REQUEST, * PMHYPROT_ENUM_PROCESS_THREADS_REQUEST;

typedef struct _MHYPROT_THREAD_INFORMATION {
	DWORD64 kernel_address;
	DWORD64 start_address;
	bool unknown;
} MHYPROT_THREAD_INFORMATION, * PMHYPROT_THREAD_INFORMATION;

typedef struct _MHYPROT_TERMINATE_PROCESS_REQUEST {
	DWORD64 response;
	DWORD process_id;
} MHYPROT_TERMINATE_PROCESS_REQUEST, * PMHYPROT_TERMINATE_PROCESS_REQUEST;

typedef struct _MHYPROT_ENUM_PROCESS_MODULES_REQUEST {
	uint32_t process_id;
	uint32_t max_count;
} MHYPROT_ENUM_PROCESS_MODULES_REQUEST, * PMHYPROT_ENUM_PROCESS_MODULES_REQUEST;

//struct HANDLE_EX {
//	HANDLE_EX() : handle() {}
//	HANDLE_EX(HANDLE_EX const&) = delete;
//	HANDLE_EX(HANDLE_EX&&) = delete;
//	HANDLE_EX& operator = (HANDLE_EX const&) = delete;
//	HANDLE_EX& operator = (HANDLE_EX&&) = delete;
//	~HANDLE_EX() { if (handle) { CloseHandle(handle);	handle = NULL; } }
//
//	HANDLE_EX& operator=(const HANDLE& h) { handle = h; return *this; }
//	HANDLE_EX& operator=(HANDLE&& h) { handle = h; return *this; }
//	operator HANDLE() const { return handle; }
//
//	HANDLE handle;
//};





namespace mhyprot {
	static HANDLE GDrvHandle;
	static DWORD64 GSeedMap[312];
	static DWORD GProcessId;

	static void RequestIOCTL(DWORD Code, void* Buffer, DWORD Size);
	static void EncryptPayload(void* Payload, DWORD size);
	static DWORD64 GenerateKey(DWORD64 seed);
	static DWORD64 FindSysmoduleAddressByName(const std::string& ModuleName);
}





Mhyprot::Mhyprot() {
	if (DriverIsExist() && !DriverIsStart())
		DriverStart();

	auto device = CreateFileA(DEVICE_NAME, GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);

	if (device == INVALID_HANDLE_VALUE || device == NULL)
		THROW_WINAPI("CreateFile", "Fail");

	mhyprot::GDrvHandle = device;
}
Mhyprot::~Mhyprot() {
	if (DriverIsExist() && DriverIsStart())
		DriverStop();

	if (mhyprot::GDrvHandle) {
		NtClose(mhyprot::GDrvHandle);
		mhyprot::GDrvHandle = NULL;
	}
}

void Mhyprot::CreateInstance() {
	static shared_ptr<Mhyprot> instance;

	if (instance)
		return;

	if (!(instance = make_shared<Mhyprot>()))
		throw bad_alloc();
}

bool mhyprot::Initialize() {
	try {
		Mhyprot::CreateInstance();

		MHYPROT_INITIALIZE initializer;
		initializer._m_002 = 0x0BAEBAEEC;
		initializer._m_003 = 0x0EBBAAEF4FFF89042;
		RequestIOCTL(MHYPROT_IOCTL_INITIALIZE, &initializer, sizeof(initializer));

		auto mhyprotAddress = FindSysmoduleAddressByName(SYSFILE_NAME);

		if (!mhyprotAddress)
			THROW_USER("FindSysmoduleAddressByName", "Not found");

		DWORD64 seedMapAddress = ReadKernelMemory<DWORD64>(mhyprotAddress + MHYPROT_OFFSET_SEEDMAP);

		if (!seedMapAddress)
			THROW_USER("ReadKernelMemory", "SeedMapAddress");

		if (!ReadKernelMemory(seedMapAddress, &GSeedMap, sizeof(GSeedMap)))
			THROW_USER("ReadKernelMemory", "SeedMap");

	} catch (const exception& e) {
#ifdef _DEBUG
		OutputDebugStringA(e.what());
#else
		UNREFERENCED_PARAMETER(e);
#endif

		return false;
	}

	return true;
}

bool mhyprot::Install() {
	try {
		if (DriverIsExist()) {
			return true;

			/*if (DriverIsStart())
				DriverStop();

			DriverDelete();*/
		}

		DriverCreate();

	} catch (const exception& e) {
#ifdef _DEBUG
		OutputDebugStringA(e.what());
#else
		UNREFERENCED_PARAMETER(e);
#endif

		return false;
	}

	return true;
}

void mhyprot::Uninstall() {
	try {

		if (!DriverIsExist())
			return;

		if (DriverIsStart())
			DriverStop();

		if (GDrvHandle) {
			NtClose(GDrvHandle);
			GDrvHandle = NULL;
		}

		DriverDelete();

	} catch (const exception& e) {
#ifdef _DEBUG
		OutputDebugStringA(e.what());
#else
		UNREFERENCED_PARAMETER(e);
#endif
	}
}

void mhyprot::RequestIOCTL(DWORD Code, void* Buffer, DWORD Size) {
	void* outBuffer = calloc(1, Size);
	DWORD outBufferSize = 0;

	if (!outBuffer)
		throw bad_alloc();

	if (!DeviceIoControl(GDrvHandle, Code, Buffer, Size, outBuffer, Size, &outBufferSize, NULL)) {
		free(outBuffer);
		THROW_WINAPI("DeviceIoControl", "Fail");
	}

	if (!outBufferSize) {
		free(outBuffer);
		THROW_USER("DeviceIoControl", "BufferSize is zero");
	}

	memcpy(Buffer, outBuffer, outBufferSize);
	free(outBuffer);
}

DWORD64 mhyprot::FindSysmoduleAddressByName(const std::string& ModuleName) {
	NTSTATUS status;
	PVOID buffer;
	ULONG alloc_size = 0x10000;
	ULONG needed_size;

	do {
		buffer = calloc(1, alloc_size);

		if (!buffer)
			throw bad_alloc();

		status = NtQuerySystemInformation(SystemModuleInformation, buffer, alloc_size, &needed_size);

		if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH) {
			free(buffer);
			THROW_NTAPI("NtQuerySystemInformation", status);
		}

		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			free(buffer);
			buffer = NULL;
			alloc_size *= 2;
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (!buffer)
		throw bad_alloc();

	auto module_information = (RTL_PROCESS_MODULES*)buffer;

	for (ULONG i = 0; i < module_information->NumberOfModules; i++) {
		auto module_entry = module_information->Modules[i];
		ULONG_PTR module_address = (ULONG_PTR)module_entry.ImageBase;

		if (module_address < MIN_ADDRESS)
			continue;

		auto module_name = (PCHAR)(module_entry.FullPathName + module_entry.OffsetToFileName);
		
		if (ModuleName.compare(module_name) == 0 ||
			std::string(module_name).find(MODULE_NAME) != std::string::npos) {
			return module_address;
		}
	}

	free(buffer);
	return 0;
}

bool mhyprot::ReadKernelMemory(DWORD64 address, void* buffer, DWORD size) {
	assert(GDrvHandle != 0 && "Please 'Initialize' before call function");

	static_assert(sizeof(DWORD) == 4 /*"invalid compiler specific size of DWORD, this may cause BSOD"*/);

	DWORD Payload_size = size + sizeof(DWORD);
	PMHYPROT_KERNEL_READ_REQUEST Payload = (PMHYPROT_KERNEL_READ_REQUEST)calloc(1, Payload_size);

	try {
		if (!Payload)
			throw bad_alloc();

		Payload->address = address;
		Payload->size = size;
		RequestIOCTL(MHYPROT_IOCTL_READ_KERNEL_MEMORY, Payload, Payload_size);

		if (!*(DWORD*)Payload) {
			memcpy(buffer, reinterpret_cast<uint8_t*>(Payload) + sizeof(DWORD), size);
			return true;
		}

	} catch (const exception& e) {
#ifdef _DEBUG
		OutputDebugStringA(e.what());
#else
		UNREFERENCED_PARAMETER(e);
#endif
	}

	return false;
}

bool mhyprot::ReadProcessMemory(DWORD64 address, void* buffer, DWORD size) {
	assert(GDrvHandle != 0 && "Please 'Initialize' before call function");
	assert(GProcessId != 0 && "Set 'ProcessID' before call function");

	MHYPROT_USER_READ_WRITE_REQUEST Payload;
	Payload.action_code = MHYPROT_ACTION_READ;  // action code
	Payload.process_id  = GProcessId;			// target process id
	Payload.address     = address;              // address
	Payload.buffer      = (DWORD64)buffer;      // our buffer
	Payload.size        = size;                 // size

	try {

		EncryptPayload(&Payload, sizeof(Payload));
		RequestIOCTL(MHYPROT_IOCTL_READ_WRITE_USER_MEMORY, &Payload, sizeof(Payload));

	} catch (const exception& e) {
#ifdef _DEBUG
		OutputDebugStringA(e.what());
#else
		UNREFERENCED_PARAMETER(e);
#endif

		return false;
	}

	return true;
}

bool mhyprot::WriteProcessMemory(DWORD64 address, void* buffer, DWORD size) {
	assert(GDrvHandle != 0 && "Please 'Initialize' before call function");
	assert(GProcessId != 0 && "Set 'ProcessID' before call function");

	MHYPROT_USER_READ_WRITE_REQUEST payload;
	payload.action_code = MHYPROT_ACTION_WRITE;    // action code
	payload.process_id  = GProcessId;               // target process id
	payload.address     = (DWORD64)buffer;         // our buffer
	payload.buffer      = address;                 // destination
	payload.size        = size;                    // size

	try {

		EncryptPayload(&payload, sizeof(payload));
		RequestIOCTL(MHYPROT_IOCTL_READ_WRITE_USER_MEMORY, &payload, sizeof(payload));

	} catch (const exception& e) {
#ifdef _DEBUG
		OutputDebugStringA(e.what());
#else
		UNREFERENCED_PARAMETER(e);
#endif

		return false;
	}

	return true;
}

bool mhyprot::GetProcessModules(deque<ModuleInfo>& result) {
	assert(GDrvHandle != 0 && "Please 'Initialize' before call function");
	assert(GProcessId != 0 && "Set 'ProcessID' before call function");
	
	const DWORD payload_context_size = static_cast<DWORD64>(64) * MHYPROT_ENUM_PROCESS_MODULE_SIZE;
	const DWORD alloc_size = sizeof(MHYPROT_ENUM_PROCESS_MODULES_REQUEST) + payload_context_size;

	auto payload = (PMHYPROT_ENUM_PROCESS_MODULES_REQUEST)calloc(1, alloc_size);

	try {
		if (!payload)
			throw bad_alloc();

		payload->process_id = GProcessId;
		payload->max_count = 64;

		RequestIOCTL(MHYPROT_IOCTL_ENUM_PROCESS_MODULES, payload, alloc_size);

		if (!payload->process_id)
			THROW_USER("payload->process_id", "Is Empty");

		const void* payload_context = reinterpret_cast<void*>(payload + 0x2);

		for (DWORD64 offset = 0x0; offset < payload_context_size; offset += MHYPROT_ENUM_PROCESS_MODULE_SIZE) {
			const std::wstring module_name = reinterpret_cast<wchar_t*>((DWORD64)payload_context + offset);
			const std::wstring module_path = reinterpret_cast<wchar_t*>((DWORD64)payload_context + (offset + 0x100));

			if (module_name.empty() && module_path.empty())
				break;

			result.push_back({ module_name, module_path });
		}
	} catch (const exception& e) {
#ifdef _DEBUG
		OutputDebugStringA(e.what());
#else
		UNREFERENCED_PARAMETER(e);
#endif
		
		if (payload)
			free(payload);

		return false;
	}

	free(payload);
	return true;
}

bool mhyprot::GetProcessThreads(deque<ThreadInfo>& result) {
	assert(GDrvHandle != 0 && "Please 'Initialize' before call function");
	assert(GProcessId != 0 && "Set 'ProcessID' before call function");

	const size_t alloc_size = 64 * MHYPROT_ENUM_PROCESS_THREADS_SIZE;
	auto payload = (PMHYPROT_ENUM_PROCESS_THREADS_REQUEST)calloc(1, alloc_size);

	try {
		if (!payload)
			throw bad_alloc();

		payload->validation_code = MHYPROT_ENUM_PROCESS_THREADS_CODE;
		payload->process_id = GProcessId;
		payload->owner_process_id = GProcessId;

		RequestIOCTL(MHYPROT_IOCTL_ENUM_PROCESS_THREADS, payload, alloc_size);

	} catch (const exception& e) {
#ifdef _DEBUG
		OutputDebugStringA(e.what());
#else
		UNREFERENCED_PARAMETER(e);
#endif

		if (payload)
			free(payload);

		return false;
	}

	if (!payload->validation_code ||
		payload->validation_code <= 0 ||
		payload->validation_code > 1000) {
		free(payload);
		return false;
	}

	const void* payload_context = reinterpret_cast<void*>(payload + 1);

	const DWORD thread_count = payload->validation_code;

	for (DWORD64 offset = 0x0; offset < (MHYPROT_ENUM_PROCESS_THREADS_SIZE * thread_count); offset += MHYPROT_ENUM_PROCESS_THREADS_SIZE) {
		const auto thread_information =	reinterpret_cast<PMHYPROT_THREAD_INFORMATION>((DWORD64)payload_context + offset);

		result.push_back({ thread_information->kernel_address, thread_information->start_address});
	}

	free(payload);
	return true;
}

DWORD mhyprot::GetSystemUptime() {
	assert(GDrvHandle != 0 && "Please 'Initialize' before call function");

	static_assert(sizeof(DWORD) == 4, "invalid compiler specific size of DWORD, this may cause BSOD");
	DWORD result;

	RequestIOCTL(MHYPROT_IOCTL_GET_SYSTEM_UPTIME, &result, sizeof(DWORD));

	return static_cast<DWORD>(result / 1000);
}

bool mhyprot::TerminateProcess() {
	assert(GDrvHandle != 0 && "Please 'Initialize' before call function");
	assert(GProcessId != 0 && "Set 'ProcessID' before call function");

	MHYPROT_TERMINATE_PROCESS_REQUEST payload{};
	payload.process_id = GProcessId;

	try {

		EncryptPayload(&payload, sizeof(payload));
		RequestIOCTL(MHYPROT_IOCTL_TERMINATE_PROCESS, &payload, sizeof(payload));

	} catch (const exception& e) {
#ifdef _DEBUG
		OutputDebugStringA(e.what());
#else
		UNREFERENCED_PARAMETER(e);
#endif

		return false;
	}

	if (!payload.response)
		return false;

	return true;
}

DWORD64 mhyprot::GenerateKey(DWORD64 seed) {
	DWORD64 k = ((((seed >> 29) & 0x555555555 ^ seed) & 0x38EB3FFFF6D3) << 17) ^ (seed >> 29) & 0x555555555 ^ seed;
	return ((k & 0xFFFFFFFFFFFFBF77u) << 37) ^ k ^ ((((k & 0xFFFFFFFFFFFFBF77u) << 37) ^ k) >> 43);
}

void mhyprot::EncryptPayload(void* Payload, DWORD size) {
	if (size % 8)
		THROW_USER("Size", "size must be 8-byte alignment");

	if (size / 8 >= 0x138)
		THROW_USER("Size", "size must be < 0x9C0");

	DWORD64* p_Payload = (DWORD64*)Payload;
	DWORD64 offset = 0;

	for (DWORD i = 1; i < size / 8; i++) {
		const DWORD64 key = GenerateKey(GSeedMap[i - 1]);
		p_Payload[i] = p_Payload[i] ^ key ^ (offset + p_Payload[0]);
		offset += 0x10;
	}
}

void mhyprot::SetProcessID(DWORD ProcessId) {
	GProcessId = ProcessId;
}

DWORD mhyprot::GetProcessID() {
	return GProcessId;
}





struct SC_HANDLE_EX {
	SC_HANDLE_EX() : handle() {}
	SC_HANDLE_EX(SC_HANDLE_EX const&) = delete;
	SC_HANDLE_EX(SC_HANDLE_EX&&) = delete;
	SC_HANDLE_EX& operator = (SC_HANDLE_EX const&) = delete;
	SC_HANDLE_EX& operator = (SC_HANDLE_EX&&) = delete;
	~SC_HANDLE_EX() { 
		if (handle) { 
			CloseServiceHandle(handle);	
			handle = NULL; 
		} 
	}

	SC_HANDLE_EX& operator=(const SC_HANDLE& h) { handle = h; return *this; }
	SC_HANDLE_EX& operator=(SC_HANDLE&& h) { handle = h; return *this; }
	operator bool() const { return handle != nullptr; }
	operator SC_HANDLE() const { return handle; }

	SC_HANDLE handle;
};

bool DriverIsExist() {
	SC_HANDLE_EX hSCManager;
	SC_HANDLE_EX hService;
	DWORD lastError;

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	if (!hSCManager)
		THROW_WINAPI("OpenSCManager", "Fail");

	if (!(hService = OpenServiceA(hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS))) {
		lastError = GetLastError();

		if (lastError != ERROR_SERVICE_DOES_NOT_EXIST)
			THROW_WINAPI("OpenService", "Fail");

		return false;
	}

	return true;
}

bool DriverIsStart() {
	SC_HANDLE_EX hSCManager;
	SC_HANDLE_EX hService;
	SERVICE_STATUS_PROCESS ssStatus;
	DWORD dwBytesNeeded;

	if (!(hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE)))
		THROW_WINAPI("OpenSCManager", "Fail");

	if (!(hService = OpenServiceA(hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS)))
		THROW_WINAPI("OpenService", "Fail");

	if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
		THROW_WINAPI("QueryServiceStatusEx", "Fail");

	if (ssStatus.dwCurrentState != SERVICE_START_PENDING && ssStatus.dwCurrentState != SERVICE_RUNNING)
		return false;

	return true;
}

void DriverStart() {
	SC_HANDLE_EX hSCManager;
	SC_HANDLE_EX hService;

	hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	if (!(hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE)))
		THROW_WINAPI("OpenSCManager", "Fail");

	if (!(hService = OpenServiceA(hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS)))
		THROW_WINAPI("OpenService", "Fail");

	if (!StartServiceA(hService, 0, NULL))
		THROW_WINAPI("OpenService", "Fail");
}

void DriverStop() {
	SC_HANDLE_EX hSCManager;
	SC_HANDLE_EX hService;
	SERVICE_STATUS ss;

	if (!(hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE)))
		THROW_WINAPI("OpenSCManager", "Fail");

	if (!(hService = OpenServiceA(hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS)))
		THROW_WINAPI("OpenServiceA", "Fail");

	if (!ControlService(hService, SERVICE_CONTROL_STOP, &ss))
		THROW_WINAPI("ControlService", "Fail");
}

void DriverDelete() {
	SC_HANDLE_EX hSCManager;
	SC_HANDLE_EX hService;
	PSTR buffer;
	string drvPath;
	DWORD needSize;

	if (!(hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE)))
		THROW_WINAPI("OpenSCManager", "Fail");

	if (!(hService = OpenServiceA(hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS)))
		THROW_WINAPI("OpenService", "Fail");

	if (!DeleteService(hService))
		THROW_WINAPI("DeleteService", "Fail");

	needSize = GetEnvironmentVariableA(SERVICE_DIR, NULL, NULL);
	buffer = (PSTR)LocalAlloc(LPTR, needSize);

	if (!buffer)
		THROW_WINAPI("LocalAlloc", "Fail");

	if (!GetEnvironmentVariableA(SERVICE_DIR, buffer, needSize))
		THROW_WINAPI("GetEnvironmentVariable", "Fail");

	drvPath = buffer;
	LocalFree(buffer);

	drvPath += "\\";
	drvPath += SERVICE_PATH;

	if (filesystem::exists(drvPath))
		filesystem::remove_all(drvPath);
}

void DriverCreate() {
	SC_HANDLE_EX hSCManager;
	SC_HANDLE_EX hService;
	PSTR buffer;
	string drvPath;
	DWORD needSize;

	needSize = GetEnvironmentVariableA(SERVICE_DIR, NULL, NULL);
	buffer = (PSTR)LocalAlloc(LPTR, needSize);

	if (!buffer)
		THROW_WINAPI("LocalAlloc", "Fail");

	if (!GetEnvironmentVariableA(SERVICE_DIR, buffer, needSize))
		THROW_WINAPI("GetEnvironmentVariable", "Fail");

	drvPath = buffer;
	LocalFree(buffer);

	drvPath += "\\";
	drvPath += SERVICE_PATH;

	if (!filesystem::exists(drvPath))
		filesystem::create_directories(drvPath);

	drvPath += "\\";
	drvPath += SERVICE_FILE;

	if (!filesystem::exists(drvPath)) {
		ofstream stream(drvPath, ios_base::out | ios_base::binary);

		if (!stream.write(reinterpret_cast<const char*>(resource::raw_driver), sizeof(resource::raw_driver))) {
			stream.close();
			throw exception(xorstr_(__FUNCTION__ " => CreateFile Fail"));
		}

		stream.close();
	}

	if (!(hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE)))
		THROW_WINAPI("OpenSCManager", "Fail");

	if (!(hService = CreateServiceA(hSCManager, SERVICE_NAME, SERVICE_NAME, SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, SERVICE_ERROR_NORMAL, drvPath.c_str(), NULL, NULL, NULL, NULL, NULL)))
		THROW_WINAPI("CreateService", "Fail");
}