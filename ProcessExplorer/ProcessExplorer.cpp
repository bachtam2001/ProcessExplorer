#include "ProcessExplorer.h"

INT main() {

	DWORD dwLevel = 0x1;
	PWTS_PROCESS_INFO_EXA pProcesses = nullptr;
	DWORD dwProcessCount = 0x0;
	std::map<int, std::string> Account, Domain;
	if (WTSEnumerateProcessesExA(WTS_CURRENT_SERVER_HANDLE,&dwLevel,WTS_ANY_SESSION,(LPSTR*)&pProcesses,&dwProcessCount)) {
		for (DWORD c = 0; c < dwProcessCount; c++) {
			if ((pProcesses + c)->ProcessId == 0) {
				continue;
			}
			LPSTR lpSID = nullptr;
			ConvertSidToStringSidA((pProcesses + c)->pUserSid, &lpSID);

			// Get the domain name and user account from SID
			CHAR szAccountName[MAX_PATH], szDomainName[MAX_PATH];
			DWORD dwMaxPathAccount = MAX_PATH;
			DWORD dwMaxPathDomain = MAX_PATH;
			SID_NAME_USE nUse;

			// Get the account and domain information from the SID of the process
			if (!LookupAccountSidA(
				nullptr,
				(pProcesses + c)->pUserSid,
				szAccountName,
				&dwMaxPathAccount,
				szDomainName,
				&dwMaxPathDomain,
				&nUse
			)) {
				Domain[(pProcesses + c)->ProcessId] = "N/A";
				Account[(pProcesses + c)->ProcessId] = "N/A";
			}
			else {
				Domain[(pProcesses + c)->ProcessId] = szDomainName;
				Account[(pProcesses + c)->ProcessId] = szAccountName;
			}
		}
		WTSFreeMemoryExA(WTSTypeProcessInfoLevel1, (PVOID)pProcesses, dwProcessCount);
		pProcesses = nullptr;
	}
	DWORD dwRet;
	DWORD dwSize = 0x0;
	NTSTATUS dwStatus = STATUS_INFO_LENGTH_MISMATCH;
	PSYSTEM_PROCESS_INFORMATION p = nullptr;

	while (TRUE) {
		if (p != nullptr) VirtualFree(p, 0x0, MEM_RELEASE);

		// try to get the information details
		p = (PSYSTEM_PROCESS_INFORMATION)VirtualAlloc(nullptr, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		dwStatus = NtQuerySystemInformation(SystemProcessInformation, (PVOID)p, (ULONG)dwSize, &dwRet);

		// if success, break the loop and proceed to printing details
		// if different error than information length mismatch, exit prorgram with error message
		if (dwStatus == STATUS_SUCCESS) { break; }
		else if (dwStatus != STATUS_INFO_LENGTH_MISMATCH) {
			VirtualFree(p, 0x0, MEM_RELEASE);
			p = nullptr;
			std::cout << "Error fetching details" << std::endl;
			return 0x1;
		}

		// use the dwRet value and add extra 8kb buffer size
		// this will become handy when new processes are created while processing this loop
		dwSize = dwRet + (2 << 12);
	}

	// Print process details
	do {
		DWORD dwPID = HandleToUlong(p->UniqueProcessId);
		FILETIME CreationTime;
		FILETIME ExitTime;
		FILETIME KernelTime;
		FILETIME UserTime;
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
		LPCWSTR exePath = (LPWSTR)VirtualAlloc(nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		GetModuleFileNameExW(hProcess, 0, (PWSTR)exePath, MAX_PATH); 

		PVOID pebAddress = GetPebAddress(hProcess);
		PVOID rtlUserProcParamsAddress;
		LPWSTR commandLineContents;
		LPCWSTR Argument = (LPWSTR)VirtualAlloc(nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (ReadProcessMemory(hProcess,
			&(((_PEB*)pebAddress)->ProcessParameters),
			&rtlUserProcParamsAddress,
			sizeof(PVOID), NULL))
		{
			UNICODE_STRING commandLine;
			if (ReadProcessMemory(hProcess,
				&(((_RTL_USER_PROCESS_PARAMETERS*)rtlUserProcParamsAddress)->CommandLine),
				&commandLine, sizeof(commandLine), NULL))
			{
				commandLineContents = (WCHAR*)malloc(commandLine.Length);		
				if (ReadProcessMemory(hProcess, commandLine.Buffer,
					commandLineContents, commandLine.Length, NULL))
				{
					std::wstring commandLineContentsString(commandLineContents, commandLine.Length/2);
					commandLineContentsString.erase(0, lstrlenW(exePath) + 2);
					wcscpy_s((PWSTR)Argument, commandLine.Length / 2, commandLineContentsString.c_str());
				}
			}
		}

		std::wcout << L"PID: " << dwPID
			<< L"\t\t\t\tImage Name: " << (p->ImageName.Buffer ? p->ImageName.Buffer : L"") << std::endl;
		std::wcout << L"Account: " << Account[dwPID].c_str()
			<< L"\t\t\t\tDomain: " << Domain[dwPID].c_str() << std::endl;
		std::wcout << L"EXE Path: " << exePath << std::endl;
		std::wcout << L"Argument: " << Argument << std::endl;

		std::wcout << L"# Handles: " << p->HandleCount
			<< L"\t\t\t\t# Threads: " << p->NumberOfThreads << std::endl;

		std::wcout << L"Virtual Size: " << GetHumanReadableSize(p->VirtualSize) << std::endl;

		std::wcout << L"Pagefile Usage: " << GetHumanReadableSize(p->PagefileUsage) << std::endl;

		std::wcout << L"Working Set Size: " << GetHumanReadableSize(p->WorkingSetSize) << std::endl;

		std::wcout << L"Quota Non-Paged Pool Usage: " << GetHumanReadableSize(p->QuotaNonPagedPoolUsage)
			<< L"\tQuota Paged Pool Usage: " << GetHumanReadableSize(p->QuotaPagedPoolUsage) << std::endl;		

		if (GetProcessTimes(hProcess, &CreationTime, &ExitTime, &KernelTime, &UserTime)) {
			std::wcout << L"Start Time: " << GetHumanReadableStartTime(CreationTime)
				<< L"\t\tExit Time : " << GetHumanReadableFileTime(ExitTime) << std::endl;
			FILETIME CurrentTime;
			GetSystemTimeAsFileTime(&CurrentTime);
			FILETIME RunTime;
			if (ExitTime.dwHighDateTime == 0 && ExitTime.dwLowDateTime == 0) {
				RunTime.dwLowDateTime = CurrentTime.dwLowDateTime - CreationTime.dwLowDateTime;
				RunTime.dwHighDateTime = CurrentTime.dwHighDateTime - CreationTime.dwHighDateTime;
			}
			else {
				RunTime.dwLowDateTime = CreationTime.dwLowDateTime - ExitTime.dwLowDateTime;
				RunTime.dwHighDateTime = CreationTime.dwHighDateTime - ExitTime.dwHighDateTime;
			}
			std::wcout << L"Running Time: " << GetHumanReadableFileTime(RunTime) << std::endl;
			FILETIME CPUTime;
			CPUTime.dwLowDateTime = KernelTime.dwLowDateTime + UserTime.dwLowDateTime;
			CPUTime.dwHighDateTime = KernelTime.dwHighDateTime + UserTime.dwHighDateTime;
			std::wcout << L"CPU Time: " << GetHumanReadableFileTime(CPUTime) << std::endl;
		};
		std::wcout << std::endl;
		// Jump to next entry
		CloseHandle(hProcess);
		p = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)p + p->NextEntryOffset);
	} while (p->NextEntryOffset != 0);

	// Free the process buffer
	VirtualFree(p, 0x0, MEM_RELEASE);
	p = nullptr;
	system("pause");
	return 0x0;
}