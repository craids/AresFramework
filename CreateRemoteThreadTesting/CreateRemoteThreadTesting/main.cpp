#include <Windows.h>
#include <Windows.h>
#include <tlhelp32.h> 
#include <shlwapi.h> 
#include <conio.h> 
#include <stdio.h> 
#include <NTSecAPI.h>
#include <DbgHelp.h>

#define WIN32_LEAN_AND_MEAN
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
#define BUFFER_SIZE 100

BOOL CreateRemoteThreadInject(DWORD ID, char * dll, char* FunctionName);

DWORD GetMainThreadId(DWORD pID);

BOOL RemoteLibraryFunction( HANDLE hProcess, LPCSTR lpModuleName, LPCSTR lpProcName, LPVOID lpParameters, SIZE_T dwParamSize, PVOID *ppReturn );

BOOL CreateRemoteThreadInject(DWORD ID, char* dll, char* FunctionName) 
{
	HANDLE Process;
	PVOID lpReturn = NULL;

	//Create the process handle
	Process = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION, FALSE, ID);
	//RemoteLibraryFunction(Process, "kernel32.dll", "LoadLibraryA", dll, strlen(dll), &lpReturn );
	HMODULE hInjected = reinterpret_cast<HMODULE>( lpReturn );

	lpReturn = NULL;
	RemoteLibraryFunction(Process, dll, FunctionName, NULL, 0, &lpReturn );
	BOOL RemoteInitialize = reinterpret_cast<BOOL>( lpReturn );

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
	
	if(!lpFunctionAddress) 
		lpFunctionAddress = GetProcAddress(LoadLibraryA(lpModuleName), lpProcName);
	
	if(!lpFunctionAddress) 
		goto ErrorHandler;

	if(lpParameters)
	{
		lpRemoteParams = VirtualAllocEx( hProcess, NULL, dwParamSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !lpRemoteParams ) 
			goto ErrorHandler;

		SIZE_T dwBytesWritten = 0;
		BOOL result = WriteProcessMemory( hProcess, lpRemoteParams, lpParameters, dwParamSize, &dwBytesWritten);
		if( !result || dwBytesWritten < 1 ) 
			goto ErrorHandler;
	}

	HANDLE hThread = CreateRemoteThread( hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpFunctionAddress, lpRemoteParams, NULL, NULL );
	
	if(!hThread)
		goto ErrorHandler;

	DWORD dwOut = 0;
	
	while(GetExitCodeThread(hThread, &dwOut)) 
	{
		if(dwOut != STILL_ACTIVE) 
		{
			DWORD hello = 0;
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

int main()
{
	DWORD processID = GetCurrentProcessId();
	char dll[100];
	GetFullPathNameA("C:\\drivers\\DeveloperDLL.dll", MAX_PATH, dll, NULL);
	if (!CreateRemoteThreadInject(processID, dll, "developerFunction"))
	{
		return 0;
	}
	else
	{
		return 1;
	}

	return 0;
}