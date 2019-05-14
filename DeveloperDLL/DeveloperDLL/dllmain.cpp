#include <stdio.h>
#include <windows.h>

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved) {
	FILE *file;
	fopen_s(&file, "C:\\Documents and Settings\\Administrator\\Desktop\\developerCall.txt", "a+");
	switch(Reason) {
	case DLL_PROCESS_ATTACH:
		fprintf(file, "DLL Process Call. \n");
		break;
	case DLL_PROCESS_DETACH:
		fprintf(file, "DLL Process Call. \n");
		break;
	case DLL_THREAD_ATTACH:
		fprintf(file, "DLL Process Call. \n");
		break;
	case DLL_THREAD_DETACH:
		fprintf(file, "DLL Process Call. \n");
		break;
	}
	fclose(file);
	return TRUE;
}

extern "C" __declspec(dllexport) int developerFunction() {
	FILE *file;
	fopen_s(&file, "C:\\Documents and Settings\\Administrator\\Desktop\\developerCall.txt", "a+");
	fprintf(file, "Developer DLL function called. \n");
	fclose(file);
	return 0;
}