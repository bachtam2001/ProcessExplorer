#pragma once
#include <windows.h>
#include <shlwapi.h>
#include <winternl.h>
#include <wtsapi32.h>
#include <processthreadsapi.h>
#include <Psapi.h>
#include <sysinfoapi.h>
#include <atlstr.h>
#include <sddl.h>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "Ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Advapi32.lib")

// NTSTATUS return codes specifically for NtQuerySystemInformation 
constexpr unsigned int STATUS_SUCCESS = 0x0;
constexpr unsigned int STATUS_INFO_LENGTH_MISMATCH = 0x0C0000004;

// Signature of NtQuerySystemInformation from winternl.h
// Placeholders IN and OUT are defined to nothing, this is just for developers to know how the parameters will be used
EXTERN_C NTSTATUS NTAPI NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID               SystemInformation,
	IN ULONG                SystemInformationLength,
	OUT PULONG              ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);


PVOID GetPebAddress(HANDLE ProcessHandle)
{
	_NtQueryInformationProcess NtQueryInformationProcess =
		(_NtQueryInformationProcess)GetProcAddress(
			GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION pbi;

	NtQueryInformationProcess(ProcessHandle, 0, &pbi, sizeof(pbi), NULL);

	return pbi.PebBaseAddress;
}

/// <summary>
/// Convert bytes to human-readable format using StrFormatByteSizeW from Shlwapi.lib
///
/// Note: In Windows 10, size is reported in base 10 rather than base 2. For example, 1 KB is 1000 bytes rather than 1024.
/// </summary>
/// <typeparam name="T">Numertic type which will be then converted to LONGLONG</typeparam>
/// <param name="size">Size in bytes</param>
/// <returns>Constant wide string containg the human-readable size buffer</returns>

template <typename T>
LPCWSTR GetHumanReadableSize(T size) {
	LPCWSTR lpSize = (LPCWSTR)VirtualAlloc(nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (StrFormatByteSizeW((LONGLONG)size, (PWSTR)lpSize, MAX_PATH) == NULL) {
		VirtualFree((LPVOID)lpSize, 0x0, MEM_RELEASE);
		lpSize = nullptr;
	}

	return lpSize;
}


LPCWSTR GetHumanReadableStartTime(FILETIME time) {
	LPCWSTR lpTime = (LPWSTR)VirtualAlloc(nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	SYSTEMTIME lpSystemTime;
	FILETIME lpLocalTime;
	FileTimeToLocalFileTime(&time, &lpLocalTime);
	FileTimeToSystemTime(&lpLocalTime, &lpSystemTime);
	std::wostringstream woss;

	woss << std::setw(2) << std::setfill(L'0') << lpSystemTime.wHour << ":"
		<< std::setw(2) << std::setfill(L'0') << lpSystemTime.wMinute << ":"
		<< std::setw(2) << std::setfill(L'0') << lpSystemTime.wSecond << " "
		<< std::setw(2) << std::setfill(L'0') << lpSystemTime.wDay << "-"
		<< std::setw(2) << std::setfill(L'0') << lpSystemTime.wMonth << "-"
		<< lpSystemTime.wYear;

	wcscpy_s((PWSTR)lpTime, MAX_PATH, woss.str().c_str());
	return lpTime;
}
LPCWSTR GetHumanReadableFileTime(FILETIME time) {
	LPCWSTR lpTime = (LPCWSTR)VirtualAlloc(nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	SYSTEMTIME lpSystemTime;
	FileTimeToSystemTime(&time, &lpSystemTime);
	std::wostringstream woss;

	woss << std::setw(2) << std::setfill(L'0') << lpSystemTime.wHour << ":"
		<< std::setw(2) << std::setfill(L'0') << lpSystemTime.wMinute << ":"
		<< std::setw(2) << std::setfill(L'0') << lpSystemTime.wSecond << "."
		<< std::setw(3) << std::setfill(L'0') << lpSystemTime.wMilliseconds;

	wcscpy_s((PWSTR)lpTime, MAX_PATH, woss.str().c_str());

	return lpTime;
}