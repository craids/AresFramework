#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char * argv[])
{
	HINSTANCE hGetProcDLL = LoadLibraryA("C:\\Documents and Settings\\Administrator\\Desktop\\LAIZYDP\\DeveloperDLL\\Release\\DeveloperDLL.dll");
	FARPROC lpfnGetProcessID = GetProcAddress(HMODULE (hGetProcDLL), "developerFunction");
	typedef int (__stdcall * pICFUNC)();
	pICFUNC MyFunction;
	MyFunction = pICFUNC(lpfnGetProcessID);
	unsigned long handle = 0;
	handle = MyFunction();
	return 0;
}