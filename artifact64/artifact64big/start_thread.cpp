
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#ifdef _M_X64
#define SET_REG(ctx, value) ctx.Rcx = (DWORD64)value
#else
#define SET_REG(ctx, value) ctx.Eax = (DWORD)value
#endif

void start_thread(HANDLE hProcess, PROCESS_INFORMATION pi, LPVOID lpStartAddress) {
	CONTEXT ctx;

	printf("[+] Running GetThreadContext ...");

	ctx.ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(pi.hThread, &ctx))
		return;
	printf(" [ + ] DONE \n");



	printf("[+] Running SetThreadContext ...");
	SET_REG(ctx, lpStartAddress);
	if (!SetThreadContext(pi.hThread, &ctx))
		return;
	printf(" [ + ] DONE \n");


	printf("[+] Running ResumeThread ...");

	ResumeThread(pi.hThread);

	printf(" [ + ] DONE \n");
}
