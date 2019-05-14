#include <iostream>
#include <windows.h>
#include <conio.h>
#include <DLLCallTechniques.h>

#pragma comment(lib, "C:\\Documents and Settings\\Administrator\\Desktop\\LAIZYDP\\DLLCallTechniques\\Release\\DLLCallTechniques.lib")

int main()
{
	int processID = GetCurrentProcessId();
	CallDLL::CallDLLFunction::CRTHook("C:\\drivers\\DeveloperDLL.dll","developerFunction", processID);
	MessageBoxA(NULL, "Original Application", "Original Application", MB_OKCANCEL);
}