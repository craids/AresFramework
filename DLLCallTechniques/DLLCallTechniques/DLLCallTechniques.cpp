#include "DLLCallTechniques.h"

namespace CallDLL
{
	int CallDLLFunction::CRTHook(char* DLLFullPath, char* FunctionName, DWORD processID)
	{
		char dll[100];
		GetFullPathNameA(DLLFullPath, MAX_PATH, dll, NULL);
		BOOL returnVal = CreateRemoteThreadInject(processID, dll, FunctionName);
		if (!returnVal)
		{
			return 1;
		}
		else
		{
			return 0;
		}

		return 0;
	}

	int CallDLLFunction::URHook(char* DLLFullPath)
	{
		HKEY hkey;
		RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, KEY_ALL_ACCESS, &hkey);
		if (RegSetValueExA(hkey, "Appinit_DLLs", 0, REG_SZ, reinterpret_cast <BYTE*>(DLLFullPath), sizeof(DLLFullPath) * sizeof(CHAR)) == ERROR_SUCCESS)
		{
			RegCloseKey(hkey);
			return 0;
		}
		return 0;
	}

	int CallDLLFunction::SWHEHook(char* DLLFullPath, char* FunctionName, DWORD processID)
	{
		HMODULE dll = LoadLibraryA(DLLFullPath);
		if(dll == NULL) {
			return -1;
		}

		HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, FunctionName);
		if(addr == NULL) {
			return -1;
		}

		HHOOK handle = SetWindowsHookExA(WH_CALLWNDPROC, addr, dll, NULL);
		if(handle == NULL) {
			return -1;
		}
		UnhookWindowsHookEx(handle);
		return 1;
	}
}

DWORD GetProcessId(IN PCHAR szExeName)
{
	DWORD dwRet = 0;
	DWORD dwCount = 0;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe = {0};
		pe.dwSize = sizeof(PROCESSENTRY32);
		BOOL bRet = Process32First(hSnapshot, &pe);

		while (bRet)
		{
			size_t i;
			char *szExeFile = (char *)malloc(BUFFER_SIZE);
			//wcstombs(szExeFile, pe.szExeFile, sizeof(pe.szExeFile));
			wcstombs_s(&i, szExeFile, (size_t)BUFFER_SIZE, pe.szExeFile, (size_t)BUFFER_SIZE);
			if (!_stricmp(szExeFile, szExeName))
			{
				dwCount++;
				dwRet = pe.th32ProcessID;
			}
			bRet = Process32Next(hSnapshot, &pe);
		}

		if (dwCount > 1)
			dwRet = 0xFFFFFFFF;

		CloseHandle(hSnapshot);
	}

	return dwRet;
}

BOOL CreateRemoteThreadInject(DWORD ID, char * dll, char* FunctionName) 
{
	HANDLE Process;
	PVOID lpReturn = NULL;

	//Create the process handle
	Process = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION, FALSE, ID);
	RemoteLibraryFunction(Process, "kernel32.dll", "LoadLibraryA", dll, strlen(dll), &lpReturn );
	HMODULE hInjected = reinterpret_cast<HMODULE>( lpReturn );

	lpReturn = NULL;
	RemoteLibraryFunction(Process, dll, FunctionName, NULL, 0, &lpReturn );
	BOOL RemoteInitialize = reinterpret_cast<BOOL>( lpReturn );
	hInjected = GetModuleHandleA((CONST char*)lpReturn);

	return RemoteInitialize;
}

DWORD GetMainThreadId(DWORD pID)
{
	LPVOID lpThreadID;
	_asm
	{
		mov eax,fs:[18h]
		add eax,36
			mov [lpThreadID],eax
	}

	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pID);
	if (hProcess == NULL)
	{
		return NULL;
	}

	DWORD tID;
	if(ReadProcessMemory(hProcess, lpThreadID, &tID, sizeof(tID), NULL) == FALSE)
	{
		CloseHandle(hProcess);
		return NULL;
	}

	CloseHandle(hProcess);
	return tID; 
}

BOOL RemoteLibraryFunction( HANDLE hProcess, LPCSTR lpModuleName, LPCSTR lpProcName, LPVOID lpParameters, SIZE_T dwParamSize, PVOID *ppReturn )
{
	LPVOID lpRemoteParams = NULL;

	LPVOID lpFunctionAddress = GetProcAddress(GetModuleHandleA(lpModuleName), lpProcName);
	if( !lpFunctionAddress ) lpFunctionAddress = GetProcAddress(LoadLibraryA(lpModuleName), lpProcName);
	if( !lpFunctionAddress ) goto ErrorHandler;

	if( lpParameters )
	{
		lpRemoteParams = VirtualAllocEx( hProcess, NULL, dwParamSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !lpRemoteParams ) goto ErrorHandler;

		SIZE_T dwBytesWritten = 0;
		BOOL result = WriteProcessMemory( hProcess, lpRemoteParams, lpParameters, dwParamSize, &dwBytesWritten);
		if( !result || dwBytesWritten < 1 ) goto ErrorHandler;
	}

	HANDLE hThread = CreateRemoteThread( hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpFunctionAddress, lpRemoteParams, NULL, NULL );
	if( !hThread ) goto ErrorHandler;

	DWORD dwOut = 0;
	while(GetExitCodeThread(hThread, &dwOut)) {
		if(dwOut != STILL_ACTIVE) {
			*ppReturn = (PVOID)dwOut;
			break;
		}
	}

	FreeLibrary(GetModuleHandleA(lpModuleName));

	return TRUE;

ErrorHandler:
	if( lpRemoteParams ) VirtualFreeEx( hProcess, lpRemoteParams, dwParamSize, MEM_RELEASE );
	return FALSE;
}