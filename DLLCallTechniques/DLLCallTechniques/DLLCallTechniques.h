#include <Windows.h>
#include <tlhelp32.h> 
#include <shlwapi.h> 
#include <conio.h> 
#include <stdio.h> 
#include <NTSecAPI.h>
#include <DbgHelp.h>
#include <Winbase.h>

#define WIN32_LEAN_AND_MEAN
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
#define BUFFER_SIZE 100

BOOL CreateRemoteThreadInject(DWORD ID, char * dll, char* FunctionName);

DWORD GetProcessId(IN PCHAR szExeName);

DWORD GetMainThreadId(DWORD pID);

BOOL RemoteLibraryFunction( HANDLE hProcess, LPCSTR lpModuleName, LPCSTR lpProcName, LPVOID lpParameters, SIZE_T dwParamSize, PVOID *ppReturn );

namespace CallDLL
{
	class CallDLLFunction
	{
	public:
		static int CRTHook(char* DLLFullPath, char* FunctionName, DWORD processID);
		static int SWHEHook(char* DLLFullPath, char* FunctionName, DWORD processID);
		static int URHook(char* DLLFullPath);
	};
}