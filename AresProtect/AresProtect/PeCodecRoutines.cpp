
#include "stdafx.h"
#include "AresProtectAsm.h"
#include "PeCodecRoutines.h"
#include <stdlib.h>
#include <time.h>
#include <list>

#ifdef _DEBUG
#define DEBUG_NEW
#endif

// -> Polymorphic En-/Decryption routine generator for per byte encryption <-
//---- STRUCTs ----
// RandNumType:
// 0 - no random num needed
// 1 - 3th byte must be a random number
// 2 - 2nd byte must be a random number
struct sPERTable{
	DWORD dwSize;
	DWORD dwEncrypt;
	DWORD dwDecrypt;
	DWORD RandNumType;
}; 
//----- EQUs -----
const int PERItems=14;
UINT WM_PROGRESS_MSG=RegisterWindowMessage(PROGRESS_MSG);
//----- CONST ----
// all opcodes are in reverse order
const sPERTable PERTable[14]={
	{0x01
	,0x90		// NOP
	,0x90		// NOP
	,0x00},		   

	{0x01
	,0xF9		// STC
	,0xF9		// STC
	,0x00},		   

	{0x01
	,0xF8		// CLC
	,0xF8		// CLC
	,0x00},

	{0x02
	,0xC0FE		// INC  AL
	,0xC8FE		// DEC  AL
	,0x00},

	{0x02
	,0x0004		// ADD AL, 0
	,0x002C		// SUB AL, 0
	,0x02},

	{0x02
	,0x002C		// SUB AL, 0
	,0x0004		// ADD AL, 0
	,0x02},

	{0x02
	,0xC102		// ADD AL, CL
	,0xC12A		// SUB AL, CL
	,0x00},

	{0x02
	,0xC12A		// SUB AL, CL
	,0xC102		// ADD AL, CL
	,0x00},

	{0x02
	,0x0034		// XOR AL, 0
	,0x0034		// XOR AL, 0
	,0x02},

	{0x03
	,0x00C8C0	// ROR  AL, 0
	,0x00C0C0	// ROL  AL, 0
	,0x01},

	{0x03
	,0x00C0C0	// ROL  AL, 0
	,0x00C8C0	// ROR  AL, 0
	,0x01},		   

	{0x03
	,0xE801EB	// Self modifing
	,0xE801EB	// Self modifing
	,0x00},		   

	{0x03
	,0xE901EB	// Self modifing
	,0xE901EB	// Self modifing
	,0x00},		   

	{0x03
	,0xC201EB	// Self modifing
	,0xC201EB	// Self modifing
	,0x00}
};

struct TCommandCode
{
	DWORD OpCode;
	UCHAR Data;
};

using namespace std;
list <TCommandCode> Encodenode,Decodenode;
list <TCommandCode>::iterator Iter;

//------- CODE ---------
void SwapDW(DWORD Value1,DWORD Value2)
{
	DWORD Value=Value1;
	Value1=Value2;
	Value2=Value;
}

void _ror(DWORD *Value,UCHAR Shift)
{
	DWORD _Value=*Value;
	_asm
	{
		XOR ECX,ECX
		MOV CL,Shift
		MOV EAX,_Value
		ROR EAX,CL
		MOV _Value,EAX
	}
	*Value=_Value;
}

void _rol(DWORD *Value,UCHAR Shift)
{
	DWORD _Value=*Value;
	_asm
	{
		XOR ECX,ECX
		MOV CL,Shift
		MOV EAX,_Value
		ROL EAX,CL
		MOV _Value,EAX
	}
	*Value=_Value;
}

DWORD random(DWORD dwRange)
{
	// generate new random number
	DWORD RValue= rand();
	// force dwRange//the last rang is RAND_MAX
	DWORD rand_by_rang=RValue%dwRange;
	return(rand_by_rang);
}

//srand should only called one time !!!
void InitRandom()
{
	//manage the random generator //srand(GetTickCount());
	srand((unsigned)time(NULL));
}
//----------------------------------------------------------------
UCHAR EncodeRoutine(UCHAR Value,UCHAR Count)
{
	UCHAR _Value=Value;
	UCHAR _Data;
	TCommandCode command;
	for(Iter=Encodenode.begin();Iter!=Encodenode.end();Iter++)
	{
		command=*Iter;
		_Data=command.Data;
		switch(command.OpCode)
		{
		case 0xC0FE:	// INC  AL
			_asm
			{
				INC _Value
			}
			break;

		case 0x0004:	// ADD AL, 0
			_asm
			{
				MOV CL,_Data
				ADD _Value,CL
			}
			break;

		case 0x002C:	// SUB AL, 0
			_asm
			{
				MOV CL,_Data
				SUB _Value,CL
			}
			break;

		case 0xC102:	// ADD AL, CL
			_asm
			{
				MOV CL,Count
				ADD _Value,CL
			}
			break;

		case 0xC12A:	// SUB AL, CL
			_asm
			{
				MOV CL,Count
				SUB _Value,CL
			}
			break;

		case 0x0034:	// XOR AL, 0
			_asm
			{
				MOV CL,_Data
				XOR _Value,CL
			}
			break;

		case 0x00C8C0:	// ROR  AL, 0
			_asm
			{
				MOV CL,_Data
				ROR _Value,CL
			}
			break;

		case 0x00C0C0:	// ROL  AL, 0
			_asm
			{
				MOV CL,_Data
				ROL _Value,CL
			}
			break;
		}
	}
	return(_Value);
}
//----------------------------------------------------------------
UCHAR DecodeRoutine(UCHAR Value,UCHAR Count)
{
	UCHAR _Value=Value;
	UCHAR _Data;
	TCommandCode command;
	for(Iter=Decodenode.begin();Iter!=Decodenode.end();Iter++)
	{
		command=*Iter;
		_Data=command.Data;
		switch(command.OpCode)
		{
		case 0xC8FE:	// DEC  AL
			_asm
			{
				DEC _Value
			}
			break;

		case 0x002C:	// SUB AL, 0
			_asm
			{
				MOV CL,_Data
				SUB _Value,CL
			}
			break;

		case 0x0004:	// ADD AL, 0
			_asm
			{
				MOV CL,_Data
				ADD _Value,CL
			}
			break;

		case 0xC12A:	// SUB AL, CL
			_asm
			{
				MOV CL,Count
				SUB _Value,CL
			}
			break;

		case 0xC102:	// ADD AL, CL
			_asm
			{
				MOV CL,Count
				ADD _Value,CL
			}
			break;

		case 0x0034:	// XOR AL, 0
			_asm
			{
				MOV CL,_Data
				XOR _Value,CL
			}
			break;

		case 0x00C0C0:	// ROL  AL, 0
			_asm
			{
				MOV CL,_Data
				ROL _Value,CL
			}
			break;

		case 0x00C8C0:	// ROR  AL, 0
			_asm
			{
				MOV CL,_Data
				ROR _Value,CL
			}
			break;
		}
	}
	return(_Value);
}
//----------------------------------------------------------------
void EncryptBuffer(char* Base,DWORD dwRVA,DWORD dwSize)
{
	UCHAR _temp;
	DWORD dwStep=dwSize/100;
	HWND m_wnd=GetActiveWindow();
	SendMessage(m_wnd,WM_PROGRESS_MSG,SETPOS_MSG,0);
	UCHAR count=UCHAR(dwSize);
	for(DWORD i=0;i<dwSize;i++)
	{
		if((i%dwStep)==0)
		{
			SendMessage(m_wnd,WM_PROGRESS_MSG,SETPOS_MSG,DWORD((i+1)/dwStep));
		}
		CopyMemory(&_temp,Base+dwRVA+i,1);//_temp=Base[dwRV+i];
		_temp=EncodeRoutine(_temp,count);
		CopyMemory(Base+dwRVA+i,&_temp,1);//Base[dwRV+i]=_temp;
		count--;
	}
}
//----------------------------------------------------------------
void DecryptBuffer(char* Base,DWORD dwRVA,DWORD dwSize)
{
	UCHAR _temp;
	UCHAR count=UCHAR(dwSize);
	for(DWORD i=0;i<dwSize;i++)
	{
		CopyMemory(&_temp,Base+dwRVA+i,1);//_temp=Base[dwRV+i];
		_temp=DecodeRoutine(_temp,count);
		CopyMemory(Base+dwRVA+i,&_temp,1);//Base[dwRV+i]=_temp;
		count--;
	}	
}
//----------------------------------------------------------------
void MakePER(char* pEncryptBuff,char* pDecryptBuff,DWORD dwSize)
{
	DWORD dwCurRandNum;
	DWORD dwRandom;
	DWORD _dwSize=dwSize;
	sPERTable pertable;
	TCommandCode DecodeCommand,EncodeCommand;
	// prepare some things
	char* pENC=new TCHAR[_dwSize];//-> EncryptBuffer will be filled from down to top
	char* pDEC=new TCHAR[_dwSize];//-> DecryptBuffer	
	// generate !
	int dwENC,dwDEC;
	dwENC=_dwSize;
	dwDEC=0;
	Encodenode.clear();
	Decodenode.clear();
	do
	{
		// get a random PER Item
		dwRandom=random(PERItems);
		pertable=PERTable[dwRandom];
		if(pertable.dwSize<=_dwSize)// check if this item is too big
		{
			//---- past the Opcode ----
			//-> encryption buffer
			if(((pertable.dwSize==1)||(pertable.dwSize==2))&&(pertable.RandNumType==0))
			{
				EncodeCommand.Data=0;
				EncodeCommand.OpCode=pertable.dwEncrypt;
				Encodenode.push_front(EncodeCommand);
				DecodeCommand.Data=0;
				DecodeCommand.OpCode=pertable.dwDecrypt;
				Decodenode.push_back(DecodeCommand);
			}
			if((pertable.RandNumType==1)||(pertable.RandNumType==2))
			{
				// generate the random num
				dwRandom=random(0xF8);
				dwRandom++;// avoid 0 !
				// update variables/pointers
				dwCurRandNum=dwRandom&0x000000FF;
				EncodeCommand.Data=UCHAR(dwCurRandNum);
				EncodeCommand.OpCode=pertable.dwEncrypt;
				Encodenode.push_front(EncodeCommand);
				DecodeCommand.Data=UCHAR(dwCurRandNum);
				DecodeCommand.OpCode=pertable.dwDecrypt;
				Decodenode.push_back(DecodeCommand);
				if(pertable.RandNumType==1) _rol(&dwCurRandNum,16);
				else _rol(&dwCurRandNum,8);
				//-> decryption buffer
				pertable.dwEncrypt=pertable.dwEncrypt | dwCurRandNum;
				pertable.dwDecrypt=pertable.dwDecrypt | dwCurRandNum;

			}
			CopyMemory(pDEC+dwDEC,&pertable.dwDecrypt,pertable.dwSize);
			dwDEC= dwDEC + pertable.dwSize;
			dwENC= dwENC - pertable.dwSize;
			CopyMemory(pENC+dwENC,&pertable.dwEncrypt,pertable.dwSize);			  
			_dwSize=_dwSize-pertable.dwSize;
		}
	}while(_dwSize!=0);
	CopyMemory(pEncryptBuff,pENC,dwSize);//-> EncryptBuffer
	CopyMemory(pDecryptBuff,pDEC,dwSize);//-> DecryptBuffer
}
