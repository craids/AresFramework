#include "stdafx.h"
#include "windows.h"
#include <iostream>
#include "conio.h"

using namespace std;

__declspec() void CallMsg();
__declspec() int MessageBox_M();
_declspec()int call_MessageBox(HWND hwnd, char * text, char * caption, UINT types);

char * text, * caption;
DWORD Buttons_and_Icons;
HWND hWnd;


//first five NOPs (0x90) will be replaced with the first five bytes of the original API
//the other 5 bytes (0xE9[jmp] and four 0x90) are there to perform a JMP exactly after our patch in the original
//API, so it can run normally. The last four NOPs (0x90) will be replaced with the size of the jump to
//the original API after the patch.
unsigned char original_bytes_for_extendedF[10] = {0x90, 0x90, 0x90 ,0x90 ,0x90, 0xE9, 0x90, 0x90 ,0x90 ,0x90};

//Hook function, when ever MessageBoxA is called it is suddenly redirected here.
__declspec(naked) void CallMsg(){
	  _asm{
		mov edi, edi
		push ebp
		mov ebp, esp
		mov eax, [ebp + 8]
		mov hWnd, eax
		mov eax, [ebp + 12]
		mov text, eax
		mov eax, [ebp + 16]
		mov caption, eax
		mov eax, [ebp + 20];
		mov Buttons_and_Icons, eax
	  }
	  char c;
	  cout<<endl<<"---- Api intercepted (MessageBoxA) ----"<<endl;
	  cout<<"Message: "<< text <<endl;
	  cout<<"Caption: "<< caption <<endl;
	  cout<<"Buttons/Icons: "<<hex<<Buttons_and_Icons<<endl;
	  cout<<"Handle Window: "<<hWnd<<endl;
	  cout<<"---- "<<endl;
	  cout<<"Do you want to let the API work? (y/n)"<<endl;
	  c = getch();

	 _asm{
	   cmp c, 'y'
	   jne out1
	   push Buttons_and_Icons
	   push caption
	   push text
	   push hWnd
	   call MessageBox_M //eax is set by the original function MessageBoxA
	   jmp finish
	   out1:
	   mov eax, -1
	finish:
	   pop ebp
	   retn 10h
	  }
}

__declspec(naked) int MessageBox_M(){
	_asm{
		NOP //mov edi, edi
		NOP //push ebp
		NOP //mov ebp, esp
		NOP //..
		NOP //..
		NOP //jmp to address of [MessageBoxA + 5]
		NOP
		NOP
		NOP
		NOP
		NOP
		NOP
	}
}

_declspec(naked)int call_MessageBox(HWND hwnd, char * text, char * caption, UINT types){
	_asm{
		push ebp
		mov ebp, esp
		push [ebp + 20]
		push [ebp + 16]
		push [ebp + 12]
		push [ebp + 8]
		call MessageBox_M
		pop ebp
		ret
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	unsigned char redirect[] = { 0xE9, 0x90, 0x90, 0x90, 0x90, 0x90};
	
	DWORD adr = (DWORD)GetProcAddress(GetModuleHandle("User32.dll"), "MessageBoxA");
	long offset = (DWORD)CallMsg - adr - 5;
	long to_original_offset = (adr + 5) - ((DWORD)MessageBox_M + 10);

	DWORD oldP;
	if (VirtualProtect((void*)adr, 5, PAGE_EXECUTE_READWRITE, &oldP)==0) MessageBox(0, "Error VirtualProtect", "info", MB_OK);
	memcpy((void*)((unsigned long)&redirect + 1), &offset, 4);
	memcpy((void*)((unsigned long)&original_bytes_for_extendedF), (void*)adr, 5);
	memcpy((void*)adr, &redirect, 5);
	VirtualProtect((void*)adr, 5, oldP, 0);

	VirtualProtect(&MessageBox_M, 10, PAGE_EXECUTE_READWRITE, &oldP);
	memcpy((void*)((unsigned long)&original_bytes_for_extendedF + 6), &to_original_offset, 4);
	memcpy((void*)MessageBox_M, &original_bytes_for_extendedF, 10);
	VirtualProtect((void*)MessageBox_M, 10, oldP, 0);

	
	int result = MessageBox(0, "I wanna be free. Do you let me?", "MSG", MB_YESNO | MB_ICONWARNING);
	if (result == IDYES){
	   cout<<"MessageBox: You have pressed YES!"<<endl;
	}else if (result == IDNO){ cout<<"MessageBox: You have pressed NO!"<<endl;
	}else if (result == -1) cout<<"MessageBox: Error, API BLOCKED!"<<endl;

	call_MessageBox(0, "This is MessageBoxA performed by an extended function", "EXTENDED CODE OVERWRITING", MB_OK | MB_ICONWARNING);

	cout<<"Press to exit..."<<endl;
	getch();

	return 0;
}
