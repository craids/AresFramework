
#include "stdafx.h"
#include "AresProtectAsm.h"
#include "PeCodecRoutines.h"
#include "PeCryptography.h"
#include <winnt.h>
#include <imagehlp.h>

#ifdef _DEBUG
#define DEBUG_NEW
#endif

//------ DEFINITIONS -------
#define IT_SIZE                 0x60
#define MAX_SECTION_NUM         20
#define MAX_IID_NUM             30
#define OEP_JUMP_ENCRYPT_NUM    'y'
#define VAR_PER_SIZE            0x30
#define SEC_PER_SIZE            0x30
#define _INVALID_HANDLE_VALUE	0xFFFFFFFF
//------- ERROR --------
#define MemErr					1
#define PEErr					2
#define FileErr					3
#define NoRoom4SectionErr		4
#define FsizeErr				5
#define SecNumErr				6
#define IIDErr					7
//----------------------------------------------------------------
//------- FUNCTION ---------
void ShowErr(unsigned char numErr);

DWORD GetFunctionRVA(void* FuncName);
DWORD GetFunctionSize(void* FuncName);
char* CopyFunction(void* FuncName);
PIMAGE_SECTION_HEADER _ImageRvaToSection(char* Base,DWORD dwRVA);
DWORD RVA2Offset(char* Base,DWORD dwRVA);

void AllocateLoaderVariables(char* Base);
void GetLoaderCryptRO(char* pFuncBody);
void GetOepJumpCodeRO(char* pFuncBody);
void OepJumpEncrypt(char* Base);
DWORD PEAlign(DWORD dwTarNum,DWORD dwAlignTo);
DWORD GetChecksum(char* Base,DWORD FileSize);

char* ReadStringFrom(char* Base,DWORD VA);
DWORD EnDeCryptString(char* Base,DWORD dwRO);
DWORD ProcessOrgIT(char* pFileImage,DWORD pITBaseRO);
void AssembleIT(char* Base,DWORD dwNewSectionRO,DWORD dwNewSectionVA);
void ProcessTlsTable(char* Base,DWORD CryptSectionVA);

PIMAGE_SECTION_HEADER AddSection(char* Base);
void CryptPE(char* Base,DWORD dwMode);
void CryptFile(char* szFname,DWORD dwProtFlags);
void PE_LOADER_CODE();
//----------------------------------------------------------------
//------- CONST --------
const char	*szDone				="Initial PE patching is done successfully!";
const char	*szDoneCap			="AresProtect | Information";
const char	*szFileErr			="Generic file access error.";
const char	*szNoPEErr			="Invalid PE file!";
const char	*szNoMemErr			="Not enough memory to run.";
const char	*szFsizeErr			="Files with a size of 0 are not allowed!";
const char	*szNoRoom4SectionErr="There is no room for a new PE section";
const char	*szSecNumErr		="Too many sections!";
const char	*szIIDErr			="Too many ImageImportDescriptors!";

const DWORD ALIGN_CORRECTION	=0x1000;// this big value is e.g. needed for WATCOM compiled files
const char	*DEPACKER_SECTION_NAME="AP";
const char	*szKernel			="KeRnEl32.dLl";
const char	*szLoadLibrary		="LoadLibraryA";
const char	*szGetProcAddress	="GetProcAddress";
//----------------------------------------------------------------
//------- DATA ---------
HANDLE	pMap			= NULL;
DWORD	dwBytesRead		= 0;
DWORD	dwBytesWritten	= 0;
char	*pMem			= NULL;
DWORD	dwFsize			= 0;
DWORD	dwOutPutSize	= 0;
DWORD	dwNewFileEnd	= 0;
DWORD	dwNTHeaderAddr	= 0;
DWORD	dwSectionNum	= 0;
DWORD	dwNewSectionRO	= 0;
DWORD	dwOrgITRVA		= 0;
HANDLE	hFile			= NULL;
char	*dllname;
//----------------------------
char	*SecEncryptBuff;
char	*SecDecryptBuff;
char	*pDepackerCode;
DWORD	DEPACKER_CODE_SIZE;
//-----------------------------
DWORD	dwRO_VAR_DECRYPTION;
DWORD   dwRO_SEC_DECRYPT;
DWORD	dwRO_OEP_JUMP_CODE_START;
DWORD	dwRO_OEP_JUMP_CODE_END;
DWORD	OEP_JUMP_CODE_SIZE; 
//----------------------------------------------------------------
//----- LOADER STRUCTS -----
struct sItInfo
{
	DWORD DllNameRVA;
	DWORD FirstThunk;
	DWORD OrgFirstThunk;
};

struct sSEH
{
	DWORD OrgEsp;
	DWORD OrgEbp;
	DWORD SaveEip;
};

struct sReThunkInfo
{
	DWORD ApiStubMemAddr;
	DWORD pNextStub;
};

struct sApiStub // UNUSED !
{
	UCHAR JumpOpc;
	DWORD JumpAddr;
};
//----------------------------------------------------------------
//----- LOADER VARIABLES -----
DWORD	dwImageBase		= 0;
DWORD	dwOrgEntryPoint	= 0;
DWORD	PROTECTION_FLAGS= 0;
DWORD	dwCalcedCRC		= 0;
DWORD	dwLoaderCRC		= 0;
DWORD	bNT				= 0;

sItInfo IIDInfo[MAX_IID_NUM];
sSEH SEH;

DWORD _LoadLibrary		= 0;
DWORD _GetProcAddress	= 0;

// some API stuff
const char	*szKernel32			= "Kernel32.dll";
DWORD		dwKernelBase		= 0;
const char	*szGetModuleHandle	= "GetModuleHandleA";
DWORD		_GetModuleHandle	= 0;
const char	*szVirtualProtect	= "VirtualProtect";
DWORD		_VirtualProtect		= 0;
const char	*szGetModuleFileName= "GetModuleFileNameA";
DWORD		_GetModuleFileName	= 0;
const char	*szCreateFile		= "CreateFileA";
DWORD		_CreateFile			= 0;
const char	*szGlobalAlloc		= "GlobalAlloc";
DWORD		_GlobalAlloc		= 0;
const char	*szGlobalFree		= "GlobalFree";
DWORD		_GlobalFree			= 0;
const char	*szReadFile			= "ReadFile";
DWORD		_ReadFile			= 0;
const char	*szGetFileSize		= "GetFileSize";
DWORD		_GetFileSize		= 0;
const char	*szCloseHandle		= "CloseHandle";
DWORD		_CloseHandle		= 0;
const char	*szIsDebuggerPresent= "IsDebuggerPresent";

// This variables won't be crypted:
IMAGE_TLS_DIRECTORY32	TlsBackup;
DWORD	dwOrgChecksum	= 0;
char	*Buff			= NULL;// buffer for some stuff, its size: 2000h(VS) - DEPACKER_CODE_SIZE
//----------------------------------------------------------------
//----- LOADER VARIABLES ADDRESS-----
DWORD	dwRO_dwImageBase;
DWORD	dwRO_dwOrgEntryPoint;
DWORD	dwRO_PROTECTION_FLAGS	;
DWORD	dwRO_dwCalcedCRC;
DWORD	dwRO_dwLoaderCRC;
DWORD	dwRO_bNT;

DWORD dwRO_IIDInfo;
DWORD dwRO_SEH;

DWORD dwRO_LoadLibrary;
DWORD dwRO_GetProcAddress;

// some API stuff
DWORD dwRO_szKernel32;
DWORD dwRO_dwKernelBase;
DWORD dwRO_szGetModuleHandle;
DWORD dwRO_GetModuleHandle;
DWORD dwRO_szVirtualProtect;
DWORD dwRO_VirtualProtect;
DWORD dwRO_szGetModuleFileName;
DWORD dwRO_GetModuleFileName;
DWORD dwRO_szCreateFile;
DWORD dwRO_CreateFile;
DWORD dwRO_szGlobalAlloc;
DWORD dwRO_GlobalAlloc;
DWORD dwRO_szGlobalFree;
DWORD dwRO_GlobalFree;
DWORD dwRO_szReadFile;
DWORD dwRO_ReadFile;
DWORD dwRO_szGetFileSize;
DWORD dwRO_GetFileSize;
DWORD dwRO_szCloseHandle;
DWORD dwRO_CloseHandle;
DWORD dwRO_szIsDebuggerPresent;

// This variables won't be crypted:
DWORD	dwRO_TlsBackup;
DWORD	dwRO_dwOrgChecksum;
DWORD	dwRO_Buff;
//----------------------------------------------------------------
//----- ERROR MESSAGES ----
//The ShowErr display message by receiving its Error Number
void ShowErr(unsigned char numErr)
{
	char *szErr=new TCHAR[64];
	switch(numErr)
	{
	case MemErr:
		strcpy(szErr,szNoMemErr);
		break;

	case PEErr:
		strcpy(szErr,szNoPEErr);
		break;

	case FileErr:
		strcpy(szErr,szFileErr);
		break;

	case NoRoom4SectionErr:
		strcpy(szErr,szNoRoom4SectionErr);
		break;

	case FsizeErr:
		strcpy(szErr,szFsizeErr);
		break;

	case SecNumErr:
		strcpy(szErr,szSecNumErr);
		break;

	case IIDErr:
		strcpy(szErr,szIIDErr);
		break;
	}
	MessageBox(GetActiveWindow(),szErr,
			   "ERROR", 
			   MB_OK | MB_ICONERROR );
}	


//----------------------------------------------------------------
//The GetFunctionRVA function returns the relative virtual 
//address (RVA) of a Function with location pointer.
DWORD GetFunctionRVA(void* FuncName)
{
	void *_tempFuncName=FuncName;
	char *ptempFuncName=PCHAR(_tempFuncName);
	DWORD _jmpdwRVA,dwRVA;
	CopyMemory(&_jmpdwRVA,ptempFuncName+1,4);
	dwRVA=DWORD(ptempFuncName)+_jmpdwRVA+5;
	return(dwRVA);
}
//----------------------------------------------------------------
//The GetFunctionSize function returns the size of 
//a Function with FuncName location pointer.
DWORD GetFunctionSize(void* FuncName)
{
	DWORD dwRVA=GetFunctionRVA(FuncName);
	char* pFuncBody=PCHAR(dwRVA);
	UCHAR _temp;
	bool notEnd=TRUE;
	char *DepackerCodeEnd=new TCHAR[10];
	DWORD l=0;
	do
	{
		CopyMemory(&_temp,pFuncBody+l,1);
		if(_temp==0xC3)
		{
			CopyMemory(DepackerCodeEnd,pFuncBody+l+0x01,10);
			DepackerCodeEnd[9]=0x00;
			if(strcmp(DepackerCodeEnd,"DEPACKEND")==0)
			{
				notEnd=FALSE;
			}
		}
		l++;
	}while(notEnd);
	return(l);
}
//----------------------------------------------------------------
//The CopyFunction function returns the pointer of
//a Function with FuncName location pointer to TCHAR pointer.
char* CopyFunction(void* FuncName)
{
	DWORD dwRVA=GetFunctionRVA(FuncName);
	DWORD dwSize=GetFunctionSize(FuncName);
	char* pFuncBody=PCHAR(dwRVA);
	char* filebuff=new TCHAR[dwSize+1];
	CopyMemory(filebuff,pFuncBody,dwSize);
	return(filebuff);
}
//----------------------------------------------------------------
//The _ImageRvaToSection function locates a relative virtual 
//address (RVA) within the image header of a file that is 
//mapped as a file and returns a pointer to the section table 
//entry for that virtual address.
PIMAGE_SECTION_HEADER _ImageRvaToSection(char* Base,DWORD dwRVA)
{
	IMAGE_SECTION_HEADER section;
	IMAGE_NT_HEADERS nt_headers;
	DWORD dwPE_Offset,SectionOffset;
	CopyMemory(&dwPE_Offset,Base+0x3c,4);
	CopyMemory(&nt_headers,Base+dwPE_Offset,sizeof(IMAGE_NT_HEADERS));
	SectionOffset=dwPE_Offset+sizeof(IMAGE_NT_HEADERS);
	for(int i=0;i<nt_headers.FileHeader.NumberOfSections;i++)
	{
		CopyMemory(&section,Base+SectionOffset+i*0x28,sizeof(IMAGE_SECTION_HEADER));
		if((dwRVA>=section.VirtualAddress) && (dwRVA<=(section.VirtualAddress+section.SizeOfRawData)))
		{
			return ((PIMAGE_SECTION_HEADER)&section);
		}
	}
	return(NULL);
}
//----------------------------------------------------------------
// calulates the Offset from a RVA
// Base    - base of the MMF
// dwRVA - the RVA to calculate
// returns 0 if an error occurred else the calculated Offset will be returned
DWORD RVA2Offset(char* Base,DWORD dwRVA)
{
	DWORD _offset;
	PIMAGE_SECTION_HEADER section;
	section=_ImageRvaToSection(Base,dwRVA);
	if(section==NULL)
	{
		return(0);
	}
	_offset=dwRVA+section->PointerToRawData-section->VirtualAddress;
	return(_offset);
}
//----------------------------------------------------------------
void AllocateLoaderVariables(char* Base)
{
	DWORD l;
	//----- LOADER VARIABLES -----
	DWORD dwRO=DEPACKER_CODE_SIZE;
	dwRO = dwRO - 1;

	//Buff						DB 0	
	dwRO = dwRO - 4;
	dwRO_Buff =dwRO;
	FillMemory(Base+dwRO,4,0x00);

	//dwOrgChecksum				DD 0
	dwRO = dwRO - 4;
	dwRO_dwOrgChecksum =dwRO;
	CopyMemory(Base+dwRO,&dwOrgChecksum,4);

	//TlsBackup					IMAGE_TLS_DIRECTORY32 <0>
	dwRO = dwRO - sizeof(IMAGE_TLS_DIRECTORY32);
	dwRO_TlsBackup =dwRO;
	CopyMemory(Base+dwRO,&TlsBackup,sizeof(IMAGE_TLS_DIRECTORY32));
	
	//szIsDebuggerPresent		DB "IsDebuggerPresent",0
	l=DWORD(strlen(szIsDebuggerPresent))+1;
	dwRO = dwRO - l;
	dwRO_szIsDebuggerPresent=dwRO;
	CopyMemory(Base+dwRO,szIsDebuggerPresent,l);

	//_CloseHandle				DD 0
	dwRO = dwRO - 4;
	dwRO_CloseHandle=dwRO;
	CopyMemory(Base+dwRO,&_CloseHandle,4);

	//szCloseHandle				DB "CloseHandle",0
	l=DWORD(strlen(szCloseHandle))+1;
	dwRO = dwRO - l;
	dwRO_szCloseHandle=dwRO;
	CopyMemory(Base+dwRO,szCloseHandle,l);

	//_GetFileSize				DD 0
	dwRO = dwRO - 4;
	dwRO_GetFileSize=dwRO;
	CopyMemory(Base+dwRO,&_GetFileSize,4);

	//szGetFileSize				DB "GetFileSize",0
	l=DWORD(strlen(szGetFileSize))+1;
	dwRO = dwRO - l;
	dwRO_szGetFileSize=dwRO;
	CopyMemory(Base+dwRO,szGetFileSize,l);

	//_ReadFile					DD 0
	dwRO = dwRO - 4;
	dwRO_ReadFile=dwRO;
	CopyMemory(Base+dwRO,&_ReadFile,4);

	//szReadFile				DB "ReadFile",0
	l=DWORD(strlen(szReadFile))+1;
	dwRO = dwRO - l;
	dwRO_szReadFile=dwRO;
	CopyMemory(Base+dwRO,szReadFile,l);

	//_GlobalFree				DD 0
	dwRO = dwRO - 4;
	dwRO_GlobalFree=dwRO;
	CopyMemory(Base+dwRO,&_GlobalFree,4);

	//szGlobalFree				DB "GlobalFree",0
	l=DWORD(strlen(szGlobalFree))+1;
	dwRO = dwRO - l;
	dwRO_szGlobalFree=dwRO;
	CopyMemory(Base+dwRO,szGlobalFree,l);	

	//_GlobalAlloc				DD 0
	dwRO = dwRO - 4;
	dwRO_GlobalAlloc=dwRO;
	CopyMemory(Base+dwRO,&_GlobalAlloc,4);

	//szGlobalAlloc				DB "GlobalAlloc",0
	l=DWORD(strlen(szGlobalAlloc))+1;
	dwRO = dwRO - l;
	dwRO_szGlobalAlloc=dwRO;
	CopyMemory(Base+dwRO,szGlobalAlloc,l);

	//_CreateFile				DD 0
	dwRO = dwRO - 4;
	dwRO_CreateFile=dwRO;
	CopyMemory(Base+dwRO,&_CreateFile,4);

	//szCreateFile				DB "CreateFileA",0
	l=DWORD(strlen(szCreateFile))+1;
	dwRO = dwRO - l;
	dwRO_szCreateFile=dwRO;
	CopyMemory(Base+dwRO,szCreateFile,l);

	//_GetModuleFileName		DD 0
	dwRO = dwRO - 4;
	dwRO_GetModuleFileName=dwRO;
	CopyMemory(Base+dwRO,&_GetModuleFileName,4);

	//szGetModuleFileName		DB "GetModuleFileNameA",0
	l=DWORD(strlen(szGetModuleFileName))+1;
	dwRO = dwRO - l;
	dwRO_szGetModuleFileName=dwRO;
	CopyMemory(Base+dwRO,szGetModuleFileName,l);

	//_VirtualProtect			DD 0
	dwRO = dwRO - 4;
	dwRO_VirtualProtect=dwRO;
	CopyMemory(Base+dwRO,&_VirtualProtect,4);

	//szVirtualProtect			DB "VirtualProtect",0
	l=DWORD(strlen(szVirtualProtect))+1;
	dwRO = dwRO - l;
	dwRO_szVirtualProtect=dwRO;
	CopyMemory(Base+dwRO,szVirtualProtect,l);

	//_GetModuleHandle			DD 0
	dwRO = dwRO - 4;
	dwRO_GetModuleHandle=dwRO;
	CopyMemory(Base+dwRO,&_GetModuleHandle,4);

	//szGetModuleHandle			DB "GetModuleHandleA",0
	l=DWORD(strlen(szGetModuleHandle))+1;
	dwRO = dwRO - l;
	dwRO_szGetModuleHandle=dwRO;
	CopyMemory(Base+dwRO,szGetModuleHandle,l);

	//dwKernelBase				DD 0
	dwRO = dwRO - 4;
	dwRO_dwKernelBase=dwRO;
	CopyMemory(Base+dwRO,&dwKernelBase ,4);

	//szKernel32				DB "Kernel32.dll",0
	l=DWORD(strlen(szKernel32))+1;
	dwRO = dwRO - l;
	dwRO_szKernel32=dwRO;
	CopyMemory(Base+dwRO,szKernel32,l);

	//_GetProcAddress			DD 0
	dwRO = dwRO - 4;
	dwRO_GetProcAddress	= dwRO;
	CopyMemory(Base+dwRO,&_GetProcAddress,4);
	
	//_LoadLibrary				DD 0
	dwRO = dwRO - 4;
	dwRO_LoadLibrary		= dwRO;
	CopyMemory(Base+dwRO,&_LoadLibrary,4);
	
	//SEH						sSEH <0>
	dwRO = dwRO - sizeof(sSEH);
	dwRO_SEH			= dwRO;
	CopyMemory(Base+dwRO,&SEH,sizeof(sSEH));

	//IIDInfo  db (SIZEOF sItInfo * MAX_IID_NUM) dup (0)
	l=sizeof(IIDInfo);
	dwRO = dwRO - sizeof(IIDInfo);
	dwRO_IIDInfo			= dwRO;
	CopyMemory(Base+dwRO,&IIDInfo,sizeof(IIDInfo));

	//bNT						DD 0
	dwRO = dwRO - 4;
	dwRO_bNT				= dwRO;
	CopyMemory(Base+dwRO,&bNT,4);

	//dwLoaderCRC				DD 0
	dwRO = dwRO - 4;
	dwRO_dwLoaderCRC		= dwRO;
	CopyMemory(Base+dwRO,&dwLoaderCRC,4);

	//dwCalcedCRC				DD 0
	dwRO = dwRO - 4;
	dwRO_dwCalcedCRC		= dwRO;
	CopyMemory(Base+dwRO,&dwCalcedCRC,4);

	//PROTECTION_FLAGS			DD 0
	dwRO = dwRO - 4;
	dwRO_PROTECTION_FLAGS	= dwRO;
	CopyMemory(Base+dwRO,&PROTECTION_FLAGS,4);

	//dwOrgEntryPoint			DD 0
	dwRO = dwRO - 4;
	dwRO_dwOrgEntryPoint	= dwRO;
	CopyMemory(Base+dwRO,&dwOrgEntryPoint,4);

	//dwImageBase				DD 0
	dwRO = dwRO - 4;
	dwRO_dwImageBase		= dwRO;
	CopyMemory(Base+dwRO,&dwImageBase,4);
}
//----------------------------------------------------------------
//return Raw Data address of Loader Crypter Codes
void GetLoaderCryptRO(char* pFuncBody)
{
	DWORD l=0;
	DWORD tmp;
	unsigned char _temp;
#ifdef _DEBUG
	do
	{
		CopyMemory(&tmp,pFuncBody+l,4);
		l++;
	}while(tmp!=0xCCCCCCCC);
	l=l+3;
#endif
	do
	{
		CopyMemory(&tmp,pFuncBody+l,4);
		l++;
	}while(tmp!=0xCCCCCCCC);
	tmp=0xC201EB90;
	CopyMemory(pFuncBody+l-1,&tmp,4);
	l=l+3;
	do
	{
		CopyMemory(&_temp,pFuncBody+l,1);
		l++;
	}while((_temp!=0xAC));
	dwRO_VAR_DECRYPTION=l;
	l=l+3;
	do
	{
		CopyMemory(&tmp,pFuncBody+l,4);
		l++;
	}while(tmp!=0xCCCCCCCC);
	tmp=0xE901EB90;
	CopyMemory(pFuncBody+l-1,&tmp,4);
	l=l+3;
	do
	{
		CopyMemory(&_temp,pFuncBody+l,1);
		l++;
	}while((_temp!=0xAC));
	dwRO_SEC_DECRYPT=l;
}
//----------------------------------------------------------------
//return Raw Data address of OEP JUMP Codes
void GetOepJumpCodeRO(char* pFuncBody)
{
	DWORD l=DEPACKER_CODE_SIZE-2;
	DWORD tmp;
	do
	{
		l--;
	}while(UCHAR(pFuncBody[l])==0xCC);
	l=l-4;
	do
	{
		CopyMemory(&tmp,pFuncBody+l,4);
		l--;
	}while(tmp!=0xCCCCCCCC);
	tmp=0xC201EB90;
	CopyMemory(pFuncBody+l+1,&tmp,4);
	dwRO_OEP_JUMP_CODE_END=l;
	l=l-4;
	do
	{
		l--;
		CopyMemory(&tmp,pFuncBody+l,4);
	}while(tmp!=0xCCCCCCCC);
	tmp=0xE901EB90;
	CopyMemory(pFuncBody+l,&tmp,4);
	l=l+4;
	dwRO_OEP_JUMP_CODE_START=l;
	OEP_JUMP_CODE_SIZE=dwRO_OEP_JUMP_CODE_END-dwRO_OEP_JUMP_CODE_START;
}
//----------------------------------------------------------------
// This functin encryptes the OEP JUMP Codes
void OepJumpEncrypt(char* Base)
{
	DWORD i;
	UCHAR _temp=0;
	UCHAR _tempC=UCHAR(OEP_JUMP_CODE_SIZE);
	for(i=dwRO_OEP_JUMP_CODE_START;i<=dwRO_OEP_JUMP_CODE_END;i++)
	{
		CopyMemory(&_temp,Base+i,1);
		_asm
		{
			MOV AL,_temp
   			ROR  AL, 2
   			ADD  AL, _tempC
   			XOR  AL, OEP_JUMP_ENCRYPT_NUM	
			MOV _temp,AL
			DEC _tempC
		}
		CopyMemory(Base+i,&_temp,1);
	}
}
//----------------------------------------------------------------
// returns aligned value
DWORD PEAlign(DWORD dwTarNum,DWORD dwAlignTo)
{	
	DWORD dwtemp;
	dwtemp=dwTarNum/dwAlignTo;
	if((dwTarNum%dwAlignTo)!=0)
	{
		dwtemp++;
	}
	dwtemp=dwtemp*dwAlignTo;
	return(dwtemp);
}
//----------------------------------------------------------------
// return Check Sum of buffer
//CYCLIC REDUNDANCY CHECKS (CRC)
DWORD GetChecksum(char* Base,DWORD FileSize)
{
	DWORD	checksum,dwhold,dwdata;
	DWORD64 dwtemp64;
	UCHAR	_temp;
	checksum=dwhold=0;
	for(DWORD i=0;i<FileSize;i++)
	{
		CopyMemory(&_temp,Base+i,1);
		dwtemp64=_temp*dwhold;
		dwdata=DWORD(dwtemp64);
		dwtemp64=dwtemp64>>32;
		dwhold=DWORD(dwtemp64);
		checksum=checksum+dwdata;
		dwhold++;
	}
	return(checksum);
}
//----------------------------------------------------------------
// This function reads the dll name strings, turn it back.
// and destroys them.
// return values:
//	char* - the dll name strings
char* ReadStringFrom(char* Base,DWORD dwRVA)
{
	int l=0;
	for(int i=0;i<255;i++)
	{
		if(Base[dwRVA+i]==0x00) break;
		l++;
	}
	char *filename=new TCHAR[l+1];
	strncpy(filename,Base+dwRVA,l+1);
	return(filename);
}
//----------------------------------------------------------------
// This function encrypts the dll name strings, saves the ImageImportDescriptors to the loader data 
// and destroys them.
// return values:
// 1 - success
// 0 - too much IID's !
DWORD EnDeCryptString(char* Base,DWORD dwRO)
{
	UCHAR _temp;
	int i = 0;
	for(i=0;i<255;i++)//DllCryptLoop
	{
		CopyMemory(&_temp,Base+dwRO+i,1);
		__asm ROR _temp,4;
		CopyMemory(Base+dwRO+i,&_temp,1);
		if(_temp==0x00) break;
	}
	if(i>223) return(0);
	return(1);
}
//----------------------------------------------------------------
// This function encrypts the dll name strings, saves the ImageImportDescriptors to the loader data 
// and destroys them.
// return values:
// 1 - success
// 0 - too much IID's !
DWORD ProcessOrgIT(char* pFileImage,DWORD pITBaseRO)
{
	DWORD stupid_num;
	DWORD dwIIDNum;
	char *dllname,*dllfunc;
	for(int i=0;i<MAX_IID_NUM;i++)// clear the IIDInfo array
	{
		IIDInfo[i].DllNameRVA=0;
		IIDInfo[i].FirstThunk=0;
		IIDInfo[i].OrgFirstThunk=0;
	}
	stupid_num=GetTickCount();// get a random number
	stupid_num=stupid_num ^ 'yong';// EDX -> stupid number :)
	// start
	IMAGE_IMPORT_DESCRIPTOR import_descriptor;// -> IID
	dwIIDNum=0;
	CopyMemory(&import_descriptor,
			   pFileImage+pITBaseRO+dwIIDNum*sizeof(IMAGE_IMPORT_DESCRIPTOR),
			   sizeof(IMAGE_IMPORT_DESCRIPTOR));
	while(import_descriptor.Name)
	{
	   	dwIIDNum++;
		if(dwIIDNum == (MAX_IID_NUM))// too much IID's ?
		{
			return 0;
		}	   
		// save IID Infos -> Loader IT data array
		IIDInfo[dwIIDNum-1].DllNameRVA=import_descriptor.Name;
		IIDInfo[dwIIDNum-1].OrgFirstThunk=import_descriptor.OriginalFirstThunk;
		IIDInfo[dwIIDNum-1].FirstThunk=import_descriptor.FirstThunk;
		//-> get dll pointer
		DWORD dllpoint=RVA2Offset(pFileImage,import_descriptor.Name);
		dllname=ReadStringFrom(pFileImage,dllpoint);
		EnDeCryptString(pFileImage,dllpoint);//-> crypt string
		dllname=ReadStringFrom(pFileImage,dllpoint);	   
		//--- CRYPT API name strings ---
  		DWORD dllfileRef=import_descriptor.OriginalFirstThunk;
  		if(!dllfileRef)
		{
			dllfileRef=import_descriptor.FirstThunk;
		}
		dllfileRef=RVA2Offset(pFileImage,dllfileRef);
		DWORD _dllfileRef=dllfileRef;
		DWORD dllfilePoint;
		CopyMemory(&dllfilePoint,pFileImage+_dllfileRef,4);
  		while( dllfilePoint!=0)// ESI -> Thunk pointer
		{			
			if((_dllfileRef&IMAGE_ORDINAL_FLAG32)==0)// is it an Ordinal Import ?
			{
				dllfilePoint=RVA2Offset(pFileImage,dllfilePoint);
  				if(dllfilePoint!=0)
				{
					dllfunc=ReadStringFrom(pFileImage,dllfilePoint+2);
					EnDeCryptString(pFileImage,dllfilePoint+2);//-> crypt string; skip the HINT
					dllfunc=ReadStringFrom(pFileImage,dllfilePoint+2);
				}
			}	      
			_dllfileRef=_dllfileRef+4;
			CopyMemory(&dllfilePoint,pFileImage+_dllfileRef,4);
		}		
  		// destroy Original IID*/
		import_descriptor.Name=stupid_num;
		import_descriptor.OriginalFirstThunk=stupid_num;
		import_descriptor.FirstThunk=stupid_num;
		import_descriptor.TimeDateStamp=stupid_num;
		import_descriptor.ForwarderChain=stupid_num;
		CopyMemory(pFileImage+pITBaseRO+(dwIIDNum-1)*sizeof(IMAGE_IMPORT_DESCRIPTOR),
				   &import_descriptor,
			       sizeof(IMAGE_IMPORT_DESCRIPTOR));
		CopyMemory(&import_descriptor,
			       pFileImage+pITBaseRO+dwIIDNum*sizeof(IMAGE_IMPORT_DESCRIPTOR),
			       sizeof(IMAGE_IMPORT_DESCRIPTOR));//-> point to next IID
	}
	return 1;
}
//----------------------------------------------------------------
// This function assembles Import Table for new section
void AssembleIT(char* Base,DWORD dwNewSectionRO,DWORD dwNewSectionRVA)
{
	char* pAddress4IT=Base+dwNewSectionRO;//-> base of the new IT		
	// Zero the memory for the new IT
	FillMemory(Base+dwNewSectionRO,IT_SIZE,0x00);
	// build a new,nice ImportTable :)
	IMAGE_IMPORT_DESCRIPTOR import_descriptor;//assume esi:ptr IMAGE_IMPORT_DESCRIPTOR
	CopyMemory(&import_descriptor,
			   pAddress4IT,
			   sizeof(IMAGE_IMPORT_DESCRIPTOR));
	// make ebx point after the terminating IID	
	DWORD dwRO=dwNewSectionRO+2*sizeof(IMAGE_IMPORT_DESCRIPTOR);
	import_descriptor.Name=dwNewSectionRVA+2*sizeof(IMAGE_IMPORT_DESCRIPTOR);// process the IID Name
	CopyMemory(Base+dwRO
			  ,szKernel,strlen(szKernel));
	dwRO=dwRO+strlen(szKernel)+1;
	// process the FirstThunk pointers
    import_descriptor.FirstThunk=dwRO-dwNewSectionRO+dwNewSectionRVA;
	DWORD dwRO_,dwRO1;
	dwRO1=dwRO+10;
	dwRO_=dwRO1-dwNewSectionRO+dwNewSectionRVA;
	CopyMemory(Base+dwRO,&dwRO_,4);
	dwRO1=dwRO1+2;

	CopyMemory(Base+dwRO1
		      ,szLoadLibrary,strlen(szLoadLibrary));
	dwRO1=dwRO1+strlen(szLoadLibrary);
	dwRO=dwRO+4;
	dwRO_=dwRO1-dwNewSectionRO+dwNewSectionRVA;
	CopyMemory(Base+dwRO,&dwRO_,4);
	dwRO1=dwRO1+2;
	CopyMemory(Base+dwRO1
			  ,szGetProcAddress,strlen(szGetProcAddress));
	CopyMemory(Base+dwNewSectionRO,
			   &import_descriptor,
			   sizeof(IMAGE_IMPORT_DESCRIPTOR));
}
//----------------------------------------------------------------
// This function relocates the Thread Local Storage (TLS) Table
// in different place
void ProcessTlsTable(char* Base,DWORD dwCryptSectionRVA)
{
	DWORD TlsDirAddr;
	// check whether there's a tls table
	IMAGE_NT_HEADERS nt_headers;
	DWORD dwPE_Offset;
	CopyMemory(&dwPE_Offset,Base+0x3c,4);//-> pointer to PE header
	CopyMemory(&nt_headers,Base+dwPE_Offset,sizeof(IMAGE_NT_HEADERS));

	TlsDirAddr=nt_headers.OptionalHeader.DataDirectory[9].VirtualAddress;
	DWORD dwRO;
	if(TlsDirAddr!=0)// check if no tls section
	{
		// get a RAW pointer to the tls table
		dwRO=RVA2Offset(Base,TlsDirAddr);//-> pointer to tls tables
		if(dwRO!=0)
		{
			dwRO_TlsBackup =DEPACKER_CODE_SIZE-(9+sizeof(IMAGE_TLS_DIRECTORY32));;
			// copy the whole TLS table into the loader data part
			CopyMemory(&TlsBackup,Base+dwRO,sizeof(IMAGE_TLS_DIRECTORY32));			
			// fix the TLS DIRECTORY VA
			DWORD dwTLS_D_VA=dwCryptSectionRVA+IT_SIZE+dwRO_TlsBackup;
			nt_headers.OptionalHeader.DataDirectory[9].VirtualAddress=dwTLS_D_VA;
			CopyMemory(Base+dwPE_Offset,&nt_headers,sizeof(IMAGE_NT_HEADERS));
			FillMemory(Base+dwRO,sizeof(IMAGE_TLS_DIRECTORY32),0x00);
		}
	}
}
//----------------------------------------------------------------
// return values:
// 0 - no room for a new section
// 1 - file already encrypted
// else: returns a pointer to the IMAGE_SECTION_HEADER struct of the new section
PIMAGE_SECTION_HEADER AddSection(char* Base)
{
	IMAGE_NT_HEADERS nt_headers;
	DWORD dwSecNum,dwPE_Offset;
	DWORD SectionOffset,newSectionOffset;
	CopyMemory(&dwPE_Offset,Base+0x3c,4);
	CopyMemory(&nt_headers,Base+dwPE_Offset,sizeof(IMAGE_NT_HEADERS));// edi -> pointer to PE header
	dwSecNum=nt_headers.FileHeader.NumberOfSections;
	// contains the size of the whole section header except the size being needed for our new section
	SectionOffset=dwPE_Offset+sizeof(IMAGE_NT_HEADERS);
	newSectionOffset=SectionOffset+dwSecNum*sizeof(IMAGE_SECTION_HEADER);
	// check whether there's room for a new section
	if(nt_headers.OptionalHeader.SizeOfHeaders<(newSectionOffset+sizeof(IMAGE_SECTION_HEADER)))
	{
		return NULL;
	}
	// create a new section
	IMAGE_SECTION_HEADER section;//-> pointer to section headers
	// go to the last section
	for(DWORD i=0;i<(dwSecNum-1);i++)
	{
		CopyMemory(&section,Base+SectionOffset+i*0x28,sizeof(IMAGE_SECTION_HEADER));
		section.Characteristics=section.Characteristics | 0x80000000;
		CopyMemory(Base+SectionOffset+i*0x28,&section,sizeof(IMAGE_SECTION_HEADER));
	}
	// start to build the new section
	IMAGE_SECTION_HEADER newsection=section;//-> pointer to the new section
	CopyMemory(&section,Base+SectionOffset+(dwSecNum-1)*0x28,sizeof(IMAGE_SECTION_HEADER));
	// VirtualAddress...
	newsection.VirtualAddress=PEAlign(section.VirtualAddress
									  +section.Misc.VirtualSize,0x1000);
	// VirtualSize..
	newsection.Misc.VirtualSize=0x2000;
	// RawSize..
	newsection.SizeOfRawData=IT_SIZE+DEPACKER_CODE_SIZE;
	// Section name
	int l=(int)strlen(DEPACKER_SECTION_NAME);
	for(int i=0;i<=7;i++)
	{
		if(i<l)newsection.Name[i]=DEPACKER_SECTION_NAME[i];
		else newsection.Name[i]=0x00;
	}
	// Characteristics
	newsection.Characteristics=0xE00000E0;
	// RawOffset
	newsection.PointerToRawData=PEAlign(section.PointerToRawData
										+section.SizeOfRawData,0x200);
	CopyMemory(Base+newSectionOffset,&newsection,sizeof(IMAGE_SECTION_HEADER));
	// update the PE header
	nt_headers.FileHeader.NumberOfSections++;
	CopyMemory(Base+dwPE_Offset,&nt_headers,sizeof(IMAGE_NT_HEADERS));
	// newsection -> will be returned
	return ((PIMAGE_SECTION_HEADER)&newsection);
}
//----------------------------------------------------------------
// Base   = pointer to file memory
// dwMode: 0 - RawCrypt mode
//         1 - VirtualCrypt mode
void CryptPE(char* Base,DWORD dwMode)
{
	DWORD SectionName;
	DWORD CryptStart;
	DWORD CryptSize;						
	IMAGE_SECTION_HEADER section;
	IMAGE_NT_HEADERS nt_headers;
	DWORD dwPE_Offset;
	DWORD SectionOffset;
	CopyMemory(&dwPE_Offset,Base+0x3c,4);
	CopyMemory(&nt_headers,Base+dwPE_Offset,sizeof(IMAGE_NT_HEADERS));// edi -> pointer to PE header
	SectionOffset=dwPE_Offset+sizeof(IMAGE_NT_HEADERS);
	for(int i=0;i<nt_headers.FileHeader.NumberOfSections;i++)
	{
		CopyMemory(&section,Base+SectionOffset+i*0x28,sizeof(IMAGE_SECTION_HEADER));
		// -> skip some special sections !
		CopyMemory(&SectionName,section.Name,4);
		if((SectionName!='crsr')&&	//rsrc
		   (SectionName!='rsr.')&&	//.rsrc
		   (SectionName!='oler')&&	//reloc
		   (SectionName!='ler.')&&	//.reloc
		   (SectionName!='PA')&&	//yC
		   (SectionName!='ade.')&&	//.edata
		   (SectionName!='adr.')&&	//.rdata
		   (SectionName!='adi.')&&	//.idata
		   (SectionName!='slt.')&&	//.tls
		   (section.PointerToRawData!=0)&&
		   (section.SizeOfRawData!=0))//-> skip also some other sections
		{
			//-> en-/decrypt it
			CryptSize=section.SizeOfRawData;
			if(dwMode==0)// (ebx is a parameter)
			{
				
				CryptStart=section.PointerToRawData;
				EncryptBuffer(Base,CryptStart,CryptSize);
			}
			else
			{
				CryptStart=section.VirtualAddress;
				DecryptBuffer(Base,CryptStart,CryptSize);
			}	   
		} 	
	}
}
//----------------------------------------------------------------
void CryptFile(char* szFname,DWORD dwProtFlags)
{
	DEPACKER_CODE_SIZE=GetFunctionSize(PE_LOADER_CODE);

	InitRandom();

	//----- MAP THE FILE -----
	hFile=CreateFile(szFname,
					 GENERIC_WRITE | GENERIC_READ,
					 FILE_SHARE_WRITE | FILE_SHARE_READ,
	                 NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile==INVALID_HANDLE_VALUE)
	{
		ShowErr(FileErr);
		return;
	}
	dwFsize=GetFileSize(hFile,0);
	if(dwFsize == 0)
	{
		CloseHandle(hFile);
		ShowErr(FsizeErr);
		return;
	}
	dwOutPutSize=dwFsize+IT_SIZE+DEPACKER_CODE_SIZE+ALIGN_CORRECTION;
	pMem=(char*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,dwOutPutSize);
	if(pMem == NULL)
	{
		CloseHandle(hFile);
		ShowErr(MemErr);
		return;
	}
	ReadFile(hFile,pMem,dwFsize,&dwBytesRead,NULL);
	// ----- check the PE Signature and get some needed values -----
	if((pMem[0]!='M')&&(pMem[1]!='Z'))
	{
		GlobalFree(pMem);
		CloseHandle(hFile);
		ShowErr(PEErr);
		return;
	}
	CopyMemory(&dwNTHeaderAddr,pMem+0x3c,4);
	if((pMem[dwNTHeaderAddr]!='P')&&(pMem[dwNTHeaderAddr+1]!='E'))
	{
		GlobalFree(pMem);
		CloseHandle(hFile);
		ShowErr(PEErr);
		return;
	}
	IMAGE_NT_HEADERS nt_headers;
	// Update local IMAGE_NT_HEADERS variable
	CopyMemory(&nt_headers,pMem+dwNTHeaderAddr,sizeof(IMAGE_NT_HEADERS));
	dwOrgITRVA=nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress;
	dwSectionNum=nt_headers.FileHeader.NumberOfSections;
	if(dwSectionNum > MAX_SECTION_NUM)
	{
		ShowErr(SecNumErr);
		return;
	}
	dwOrgEntryPoint=nt_headers.OptionalHeader.AddressOfEntryPoint;
	dwImageBase=nt_headers.OptionalHeader.ImageBase;	

	//----- DELETE Bound Import & IAT DIRECTORIES -----
	// Update local IMAGE_NT_HEADERS variable
	CopyMemory(&nt_headers,pMem+dwNTHeaderAddr,sizeof(IMAGE_NT_HEADERS));
	nt_headers.OptionalHeader.DataDirectory[11].VirtualAddress=0;
	nt_headers.OptionalHeader.DataDirectory[11].Size=0;
	nt_headers.OptionalHeader.DataDirectory[12].VirtualAddress=0;
	nt_headers.OptionalHeader.DataDirectory[12].Size=0;
	CopyMemory(pMem+dwNTHeaderAddr,&nt_headers,sizeof(IMAGE_NT_HEADERS));

	//----- ENCRYPT DLL/API NAMES & SAVE IT & DESTROY IID's -----
	DWORD dwOrgITRO=RVA2Offset(pMem,dwOrgITRVA);
	if(ProcessOrgIT(pMem,dwOrgITRO)==0)
	{
		GlobalFree(pMem);
		CloseHandle(hFile);
		ShowErr(IIDErr);
		return;
	}
	//----- ADD THE PACKER SECTION -----
	PIMAGE_SECTION_HEADER pnewsection;
	IMAGE_SECTION_HEADER newsection;
	pnewsection=AddSection(pMem);//	assume -> IMAGE_SECTION_HEADER
	newsection=*pnewsection;
	if(pnewsection==NULL)
	{
		GlobalFree(pMem);
		CloseHandle(hFile);
		ShowErr(NoRoom4SectionErr);
		return;	
	}
	pnewsection=NULL;
	// Update local IMAGE_NT_HEADERS variable
	CopyMemory(&nt_headers,pMem+dwNTHeaderAddr,sizeof(IMAGE_NT_HEADERS));

	pDepackerCode=new TCHAR[DEPACKER_CODE_SIZE];
	pDepackerCode=CopyFunction(PE_LOADER_CODE);
	GetOepJumpCodeRO(pDepackerCode);
	GetLoaderCryptRO(pDepackerCode);

    //----- CREATE PACKER IMPORT TABLE -----
	dwNewSectionRO=newsection.PointerToRawData;
	AssembleIT(pMem,dwNewSectionRO,newsection.VirtualAddress);

	//---- REPLACE TLS TABLE -----
	ProcessTlsTable(pMem,newsection.VirtualAddress);

	//------ ENCRYPT THE SECTIONS -----
	// generate PER
	SecEncryptBuff=new TCHAR[SEC_PER_SIZE];
	SecDecryptBuff=new TCHAR[SEC_PER_SIZE];

	MakePER(SecEncryptBuff,SecDecryptBuff,SEC_PER_SIZE);
	CopyMemory(pDepackerCode+dwRO_SEC_DECRYPT,
			   SecDecryptBuff,
			   SEC_PER_SIZE);	

	// encrypt !
	CryptPE(pMem,0);

	// ----- UPDATE PE HEADER -----	
	// ImportTable RVA ...
	// Update local IMAGE_NT_HEADERS variable
	CopyMemory(&nt_headers,pMem+dwNTHeaderAddr,sizeof(IMAGE_NT_HEADERS));
	nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress=newsection.VirtualAddress;
	// EntryPoint...
	nt_headers.OptionalHeader.AddressOfEntryPoint=newsection.VirtualAddress+IT_SIZE;
	// SizeOfImage ...
	nt_headers.OptionalHeader.SizeOfImage=newsection.VirtualAddress+newsection.Misc.VirtualSize;
	CopyMemory(pMem+dwNTHeaderAddr,&nt_headers,sizeof(IMAGE_NT_HEADERS));//-> pointer to PE header

	// ----- CALCULATE THE NEW EOF -----
	dwNewFileEnd=dwNewSectionRO+IT_SIZE+DEPACKER_CODE_SIZE;
	
	// ----- COPY LOADER CODE TO FILE MEMORY & DO CHECKSUM STUFF ------
	DWORD dwRO_yC;
	dwRO_yC=dwNewSectionRO+IT_SIZE;
	
	PROTECTION_FLAGS=dwProtFlags;// save protection flags...
	
	AllocateLoaderVariables(pDepackerCode);
		
	//----- ENCRYPT OEP JUMP CODE -----;
	OepJumpEncrypt(pDepackerCode);
	
	//----- ENCRYPT LOADER -----
	// generate PER
	SecEncryptBuff=new TCHAR[VAR_PER_SIZE];
	SecDecryptBuff=new TCHAR[VAR_PER_SIZE];
	 
	MakePER(SecEncryptBuff,SecDecryptBuff,VAR_PER_SIZE);
	CopyMemory(pDepackerCode+dwRO_VAR_DECRYPTION,
			   SecDecryptBuff,
			   VAR_PER_SIZE);	

	// encryption !
	EncryptBuffer(pDepackerCode,
				  dwRO_VAR_DECRYPTION+0x3+VAR_PER_SIZE,
				  DEPACKER_CODE_SIZE-
				  (dwRO_VAR_DECRYPTION+0x04+VAR_PER_SIZE
				  +sizeof(IMAGE_TLS_DIRECTORY32)+0x08));
	CopyMemory(pMem+dwRO_yC,pDepackerCode,DEPACKER_CODE_SIZE);

	//----- CALCULATE CHECKSUM -----
	dwOrgChecksum=GetChecksum(pMem,dwRO_yC+dwRO_OEP_JUMP_CODE_START-1);

	//----- PASTE CHECKSUM ------
	CopyMemory(pMem+dwRO_yC+dwRO_dwOrgChecksum,&dwOrgChecksum,4);

	// ----- WRITE FILE MEMORY TO DISK -----
	SetFilePointer(hFile,0,NULL,FILE_BEGIN);
	WriteFile(hFile,pMem,dwOutPutSize,&dwBytesWritten,NULL);
	
	// ------ FORCE CALCULATED FILE SIZE ------
	SetFilePointer(hFile,dwNewFileEnd,NULL,FILE_BEGIN);
	SetEndOfFile(hFile);

	MessageBox(GetActiveWindow(),szDone,szDoneCap,MB_ICONINFORMATION);

	// ----- CLEAN UP -----
	GlobalFree(pMem);
	CloseHandle(hFile);
}
//----------------------------------------------------------------
void PE_LOADER_CODE()
{
	_asm
	{
	//----------------------------------------------------------
	//-------------- START OF THE PE LOADER CODE ---------------
DepackerCode:
	PUSHAD
	// get base ebp
	CALL CallMe
CallMe:	
	POP EBP
	SUB EBP,OFFSET CallMe
	//----------------------------------------------------------
	//---------------- DECRYPT LOADER VARIABLES ----------------
	MOV ECX,OFFSET LOADER_CRYPT_END
	SUB ECX,OFFSET LOADER_CRYPT_START//ecx->CRYPT_LOADER_SIZE
	MOV EDX,EBP
	ADD EDX,OFFSET LOADER_CRYPT_START
	LEA EDI,[EDX]
	MOV ESI,EDI
	XOR EAX,EAX
	JMP VarDecryptionLoop
	INT 3
	INT 3
	INT 3
	INT 3
VarDecryptionLoop:
		LODS BYTE PTR DS:[ESI]
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		STOS BYTE PTR ES:[EDI]
	LOOP VarDecryptionLoop
LOADER_CRYPT_START:
	//----------------------------------------------------------
	//---------------------- DETECT WinNT ----------------------
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_bNT
	MOV EAX,[ESP+020h]
	INC EAX
	JS  NoNT
		MOV DWORD PTR [EDX], 1
	JMP IsNT
NoNT:
		MOV DWORD PTR [EDX], 0	
IsNT:
	//----------------------------------------------------------
	//----------------- Get CRC OF LOADER CODE -----------------
	MOV EDX,EBP
	ADD EDX,OFFSET DepackerCode
	LEA EAX,DWORD PTR [EDX]
	//OFFSET OEP_JUMP_CODE_START - OFFSET DepackerCode
	MOV ECX,OFFSET OEP_JUMP_CODE_START 
	SUB	ECX,OFFSET DepackerCode
	CALL _GetCheckSum
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwLoaderCRC
	MOV DWORD PTR [EDX], EAX   
	//----------------------------------------------------------
	//------------------------ SI Check 1 ----------------------
	//.IF [EBP+PROTECTION_FLAGS]== CHECK_SI_FLAG
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_PROTECTION_FLAGS
	TEST DWORD PTR [EDX],CHECK_SI_FLAG
	JZ SkipSICheck
		// install SEH frame
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_SEH
		LEA ESI,[EDX]
		//ASSUME ESI : PTR sSEH
		MOV EDX,EBP
		ADD EDX,OFFSET SICheck1_SP
		LEA EAX,[EDX]
		MOV DWORD PTR DS:[ESI+8],EAX//[ESI].SaveEip
		//ASSUME ESI : NOTHING
		MOV EDI,EBP

		MOV EDX,EBP
		ADD EDX,OFFSET SehHandler1
		LEA EAX,[EDX]
		XOR EBX,EBX
		PUSH EAX
		PUSH DWORD PTR FS:[EBX]
		MOV DWORD PTR FS:[EBX], ESP

		// 0 - SI not found
		// 1 - SI found
    	MOV AX,04h
    	JMP SM1
    	INT	3//DB 0FFh
SM1:
      	INT 3
    	
SICheck1_SP:
		MOV  EBP, EDI
		// uninstall SEH frame
		XOR  EBX, EBX
    	POP  DWORD PTR FS:[EBX]
    	ADD  ESP, 4
		//.IF AL != 4
		CMP AL,4	
		JE SkipSICheck
			// exit
			JMP SM2
			INT 3//DB 0E9h
SM2: 		POPAD
			RETN
		//.ENDIF
SkipSICheck:
	//.ENDIF
	//----------------------------------------------------------
	//----------------- GET BASE API ADDRESSES -----------------
	// find the ImageImportDescriptor and grab dll addresses
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwImageBase
	MOV EAX,DWORD PTR [EDX]
	ADD EAX,[EAX+03Ch]
	ADD EAX,080h
	MOV ECX,DWORD PTR [EAX]	// ecx contains the VirtualAddress of the IT
	ADD ECX,DWORD PTR [EDX]
	ADD ECX,010h				//ecx points to the FirstThunk address of the IID
	MOV EAX,DWORD PTR [ECX]
	ADD EAX,DWORD PTR [EDX]
	MOV EBX,DWORD PTR [EAX]
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_LoadLibrary
	MOV [EDX],EBX
	ADD EAX,04h
	MOV EBX,DWORD PTR [EAX]
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_GetProcAddress
	MOV DWORD PTR [EDX],EBX	
	//----- GET ALL OTHER API ADDRESSES -----
	// get kernel base
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_szKernel32
	LEA EAX,[EDX]
	PUSH EAX
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_LoadLibrary
	CALL [EDX]
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwKernelBase
	MOV ESI,EAX	// esi -> kernel base
	MOV DWORD PTR [EDX], EAX
	//KernelBase=LoadLibrary(szKernel32);

	//-> GetModuleHandle
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_szGetModuleHandle
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_GetModuleHandle
	MOV [EDX],EAX
	//GetModuleHandle=GetProcAddress(KernelBase,szGetModuleHandle);
	
	//-> VirtualProtect
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_szVirtualProtect
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_VirtualProtect
	MOV [EDX],EAX
	//VirtualProtect=GetProcAddress(KernelBase,szVirtualProtect);
	
	//-> GetModuleFileName
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_szGetModuleFileName
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_GetModuleFileName
	MOV [EDX],EAX
	//GetModuleFileName=GetProcAddress(KernelBase,szGetModuleFileName);
	
	//-> CreateFile
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_szCreateFile
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_CreateFile
	MOV [EDX],EAX
	//CreateFile=GetProcAddress(KernelBase,szCreateFile);
	
	//-> GlobalAlloc
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_szGlobalAlloc
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_GlobalAlloc
	MOV [EDX],EAX
	//GlobalAlloc=GetProcAddress(KernelBase,szGlobalAlloc);

	//-> GlobalFree
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_szGlobalFree
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_GlobalFree
	MOV [EDX],EAX
	//GlobalFree=GetProcAddress(KernelBase,szGlobalFree);
	
	//-> ReadFile
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_szReadFile
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_ReadFile
	MOV [EDX],EAX
	//ReadFile=GetProcAddress(KernelBase,szReadFile);

	//-> GetFileSize
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_szGetFileSize
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_GetFileSize
	MOV [EDX],EAX
	//GetFileSize=GetProcAddress(KernelBase,szGetFileSize);
	
	//-> CloseHandle
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_szCloseHandle
	LEA EAX,[EDX]
	CALL DoGetProcAddr
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_CloseHandle
	MOV [EDX],EAX
	//CloseHandle=GetProcAddress(KernelBase,szCloseHandle);

	// FUNNY JUMP :)
	MOV EDX,EBP
	ADD EDX,OFFSET LoaderContinue1
	LEA EAX, [EDX]
	PUSH EAX
	RETN
//---------------------
// it's in an own function to keep a the loader code small
// EAX = address of API string
// ESI = target dll base	
DoGetProcAddr:
	PUSH EAX
	PUSH ESI
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_GetProcAddress
	CALL [EDX]
	//FARPROC GetProcAddress(HMODULE hModule,LPCSTR lpProcName);
	RETN
//---------------------
LoaderContinue1:
	//----------------------------------------------------------
	//------------------------ ANTI DUMP -----------------------
	//.IF [EBP+PROTECTION_FLAGS]== ANTI_DUMP_FLAG
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_PROTECTION_FLAGS
	TEST DWORD PTR [EDX],ANTI_DUMP_FLAG
	JZ LetDumpable
		PUSH FS:[30h]
		POP EAX
		TEST EAX,EAX
		JS fuapfdw_is9x					// detected Win 9x
//fuapfdw_isNT:
			MOV EAX,[EAX+0Ch]
			MOV EAX,[EAX+0Ch]
			MOV DWORD PTR [EAX+20h],1000h // increase size variable
			JMP fuapfdw_finished
fuapfdw_is9x:
			PUSH 0
			MOV EBX,EBP
			ADD EBX,OFFSET _RO_GetModuleHandle
			CALL [EBX]
			//HMODULE GetModuleHandle(LPCTSTR lpModuleName);
			TEST EDX,EDX
			JNS fuapfdw_finished		// Most probably incompatible!!!
			CMP DWORD PTR [EDX+8],-1
			JNE fuapfdw_finished		// Most probably incompatible!!!
			MOV EDX,[EDX+4]				// get address of internaly used
										// PE header
			MOV DWORD PTR [EDX+50h],1000h // increase size variable
fuapfdw_finished:
LetDumpable:
	//.ENDIF
	//----------------------------------------------------------
	//---------------- GET HEADER WRITE ACCESS -----------------
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwImageBase
	MOV EDI,DWORD PTR [EDX]
	ADD EDI,DWORD PTR [EDI+03Ch]// edi -> pointer to PE header
	//assume edi : ptr IMAGE_NT_HEADERS
	MOV ESI,DWORD PTR [EDX]
	MOV ECX,DWORD PTR [EDI+0x54]//.OptionalHeader.SizeOfHeaders
	//assume edi : nothing
		
	// fix page access
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_Buff
	LEA EAX,[EDX]
	PUSH EAX
	PUSH PAGE_READWRITE
	PUSH ECX
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwImageBase
	PUSH [EDX]
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_VirtualProtect
	CALL [EDX]
	//VirtualProtect(dwImageBase,
	//				 OptionalHeader.SizeOfHeaders,
	//				 PAGE_READWRITE,
	//				 *Buff);

	//----------------------------------------------------------
	//---------------------- CALCULATE CRC ---------------------
	//.IF [EBP+PROTECTION_FLAGS]== CHECK_HEADER_CRC
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_PROTECTION_FLAGS
	TEST DWORD PTR [EDX],CHECK_HEADER_CRC
	JZ DontCheckCRC
		// get the calling exe filename
		push MAX_PATH
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_Buff
		LEA EDI,[EDX]
		PUSH EDI// edi -> filename
		PUSH 0
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_GetModuleFileName
		CALL [EDX]
		//FileName=GetModuleFileName(NULL,Buff,MAX_PATH);

		// map it...
		PUSH 0
		PUSH FILE_ATTRIBUTE_NORMAL
		PUSH OPEN_EXISTING
		PUSH NULL
		PUSH FILE_SHARE_READ
		PUSH GENERIC_READ
		PUSH EDI
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_CreateFile
		CALL [EDX]
		//handle=CreateFile(FileName,
		//	                GENERIC_READ,FILE_SHARE_READ,NULL,
		//	                OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);

		CMP EAX,_INVALID_HANDLE_VALUE
		JNE HANDLE_IS_VALID1
			XOR EAX,EAX
			JMP SkipChecksumCalc
HANDLE_IS_VALID1:
		MOV EDI,EAX	// edi -> file handle
	
		PUSH NULL
		PUSH edi
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_GetFileSize
		CALL [EDX]
		//filesize=GetFileSize(handle,NULL);

		MOV EDX,OFFSET DepackerCodeEND//OEP_JUMP_CODE_END
		SUB EDX,OFFSET OEP_JUMP_CODE_START//EDX->CHECKSUM_SKIP_SIZE
		SUB EAX,EDX
		SUB EAX,2
		XCHG EAX,ESI// esi -> filesize
		
		PUSH ESI
		PUSH GMEM_FIXED+GMEM_ZEROINIT
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_GlobalAlloc
		CALL [EDX]
		//hglobal=GlobalAlloc(GMEM_FIXED|GMEM_ZEROINIT,filesize);

		//.IF(hglobal==NUL;)
		CMP EAX,NULL
		JNE ALLOCATE_IS_VALID
			JMP SkipChecksumCalcAndCleanUp
ALLOCATE_IS_VALID:
		//.ENDIF

		XCHG EAX,EBX// ebx -> mem base
	
		PUSH NULL
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_Buff
		LEA EAX,[EDX]

		PUSH EAX
		PUSH ESI
		PUSH EBX
		PUSH EDI
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_ReadFile
		CALL [EDX]
		//BOOL ReadFile(handle,hglobal,filesize,Buff,NULL);

		// get the checksum
		MOV EAX,EBX
		MOV ECX,ESI
		PUSH EBX// [ESP] -> hMem
		PUSH EDI// EDI = hFile
	
		CALL _GetCheckSum
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_dwCalcedCRC
		MOV [EDX],EAX
	
		POP  EDI
		POP  EBX
		// the calculated CRC will be compared at the start of the InitIT function >:-)
		// FUNNY JUMP :)
		MOV EDX,EBP
		ADD EDX,OFFSET AfterCRCCalcContinue
		LEA  EAX,[EDX]
		PUSH EAX
		RETN
	JMP AfterDeCryptionContinue

//---------------------
//-> Start of GetCheckSum
_GetCheckSum:
	// EAX = file image base
	// ECX = filesize	
	MOV EDI,EAX	// edi -> data pointer
	XOR EAX,EAX	// eax -> current bytes
	XOR EBX,EBX	// ebx -> current checksum
	XOR EDX,EDX	// edx -> Position (zero based)
	// start calculation
CheckSumLoop:
		MOV AL,BYTE PTR [EDI]
		MUL EDX
		ADD EBX,EAX 
		INC EDX
   	INC EDI   	
	LOOP CheckSumLoop
   	XCHG EAX,EBX// EAX -> checksum
	RETN
//-> End of GetChecksum
//---------------------
AfterCRCCalcContinue:
		// clean up
		PUSH EBX
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_GlobalFree
		CALL [EDX]//GlobalFree(checksum);

		XCHG ESI,EAX
SkipChecksumCalcAndCleanUp:	
		PUSH EAX
		PUSH EDI
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_CloseHandle
		CALL [EDX]//CloseHandle(handle);	
		POP EAX
SkipChecksumCalc:
DontCheckCRC:
	//.ENDIF
	//----------------------------------------------------------
	//----------------------- DECRYPTION -----------------------
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwImageBase
	MOV EAX,[EDX]
	MOV EBX,1
	CALL _CryptPE
	MOV EDX,EBP
	ADD EDX,OFFSET AfterDeCryptionContinue
	LEA EAX,[EDX]
	PUSH EAX
	RETN
//-----------------------------------------------------
//----------------- SECTIONS DECRYPTER ----------------
// void DecryptBuffer(char* Base,DWORD dwRV,DWORD dwSize)
// esi = CryptStart
// ecx = CryptSize
_DecryptBuff:
	MOV EDI,ESI
	JMP DecryptBuffLoop
	INT 3
	INT 3
	INT 3
	INT 3
DecryptBuffLoop:
		LODS BYTE PTR DS:[ESI]
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		ADD BYTE PTR DS:[EAX],AL
		STOS BYTE PTR ES:[EDI]
	LOOP DecryptBuffLoop
RETN
//-----------------------------------------------------
//----------------- SECTIONS ENCRYPTER ----------------
// void EncryptBuffer(char* Base,DWORD dwRVA,DWORD dwSize)
// esi = CryptStart
// ecx = CryptSize
_EncryptBuff:
	MOV EDI,ESI
EncryptBuffLoop:
		MOV EDI,ESI
		LODS BYTE PTR DS:[ESI]
		//SecEncryptBuff DB SEC_PER_SIZE DUP (0)
		STOS BYTE PTR ES:[EDI]
	LOOP EncryptBuffLoop
RETN
//------------------------------------------------------
// void CryptPE(char* Base,DWORD dwMode)
//------------------------------------------------------
// eax = pointer to file memory
// ebx: 0 - RawCrypt mode
//      1 - VirtualCrypt mode
_CryptPE:
	MOV EDI,EAX
	ADD EDI,[EDI+3Ch]
	//assume edi : ptr IMAGE_NT_HEADERS		; edi -> PE header
	MOV ESI,EDI
	ADD ESI,0F8h
	//assume esi : ptr IMAGE_SECTION_HEADER		; esi -> Section header
	XOR EDX,EDX
	//.REPEAT	   
SECTION_IS_NOT_ZERO:
		// -> skip some special sections !
		//.IF dword ptr [esi].Name1 == ('crsr')
		CMP DWORD PTR DS:[ESI],'crsr'//rsrc
			JZ __LoopEnd
		//.ENDIF

		//.IF dword ptr [esi].Name1 == ('rsr.')
		CMP DWORD PTR DS:[ESI],'rsr.'//.rsrc
			JZ __LoopEnd
		//.ENDIF

		//.IF dword ptr [esi].Name1 == ('oler')
		CMP DWORD PTR DS:[ESI],'oler'//reloc
			JZ __LoopEnd
		//.ENDIF

		//.IF dword ptr [esi].Name1 == ('ler.')
		CMP DWORD PTR DS:[ESI],'ler.'//.reloc
			JZ __LoopEnd
		//.ENDIF

		//.IF dword ptr [esi].Name1 == ('Cy')
		CMP DWORD PTR DS:[ESI],'PA'//yC
			JZ __LoopEnd
		//.ENDIF

		//.IF dword ptr [esi].Name1 == ('ade.')
		CMP DWORD PTR DS:[ESI],'ade.'//.edata
			JZ __LoopEnd
		//.ENDIF

		//.IF dword ptr [esi].Name1 == ('adr.')
		CMP DWORD PTR DS:[ESI],'adr.'//.rdata
			JZ __LoopEnd
		//.ENDIF

		//.IF dword ptr [esi].Name1 == ('adi.')
		CMP DWORD PTR DS:[ESI],'adi.'//.idata
			JZ __LoopEnd
		//.ENDIF

		//.IF dword ptr [esi].Name1 == ('slt.')
		CMP DWORD PTR DS:[ESI],'slt.'//.tls
			JZ __LoopEnd
		//.ENDIF
		//-> skip also some other sections
		//.IF [esi].PointerToRawData == 0 || [esi].SizeOfRawData == 0
		CMP DWORD PTR DS:[ESI+14h],0
		JZ __LoopEnd
		CMP DWORD PTR DS:[ESI+10h],0
		JZ __LoopEnd
		//.ENDIF
   
	   //-> en-/decrypt it

		PUSHAD
		MOV ECX,DWORD PTR DS:[ESI+10h]	//[esi].SizeOfRawData
		//.IF ebx == 0	// (ebx is a parameter)
		OR EBX,EBX
		JNZ MODE_IS_1
			MOV ESI,DWORD PTR DS:[ESI+14h]//[esi].PointerToRawData
			ADD ESI, EAX
			CALL _EncryptBuff
			JMP CHECKMODE_FINISH
		//.ELSE
MODE_IS_1:
			MOV ESI,DWORD PTR DS:[ESI+0Ch]//[esi].VirtualAddress
			ADD ESI,EAX
			CALL _DecryptBuff
		//.ENDIF
CHECKMODE_FINISH:
		// FUNNY JUMP :)
		MOV EDX,EBP
		ADD EDX,OFFSET SecDecryptContinue1
		LEA EAX, [EDX]
		PUSH EAX
		RETN
		MOV EAX,00h
		INT 13
SecDecryptContinue1:	   
		POPAD
__LoopEnd:   
		ADD ESI,28h//SIZEOF IMAGE_SECTION_HEADER
		INC EDX
	//.UNTIL DX==[EDI].FileHeader.NumberOfSections
	CMP DX,WORD PTR DS:[EDI+6]
	JNZ SECTION_IS_NOT_ZERO
	//assume esi : nothing
	//assume edi : nothing*/
	RETN

AfterDeCryptionContinue:
   	//------ PREPARE THE OEP JUMP EXCEPTION :) ------
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwImageBase
	MOV EBX,[EDX]
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwOrgEntryPoint
	ADD EBX,[EDX]
	ROR EBX,7
	MOV [ESP+010h],EBX
	MOV EDX,EBP
	ADD EDX,OFFSET SehHandler_OEP_Jump
	LEA EBX,[EDX]
	MOV [ESP+01Ch],EBX
	
	//----- SET Index Variable of TLS table to 0 -----
	// check whether there's a tls table
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwImageBase
	MOV EDI,DWORD PTR [EDX]
	ADD EDI,DWORD PTR [EDI+03Ch]// edi -> pointer to PE header
	//assume edi : ptr IMAGE_NT_HEADERS
	MOV EBX,DWORD PTR [EDI+0C0h]//OptionalHeader.DataDirectory[9].VirtualAddress
	//assume edi : nothing
	CMP EBX,0	// no tls section
	JZ SkipTlsFix
	ADD EBX,DWORD PTR [EDX]	// ebx -> pointer to tls table
	//assume ebx : ptr IMAGE_TLS_DIRECTORY32
	MOV EAX,DWORD PTR [EBX+08h]
	MOV DWORD PTR [EAX],0
	//assume ebx : nothing	
SkipTlsFix:
	//----- CRC COMPARE -----
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwCalcedCRC
	MOV EAX,DWORD PTR [EDX]

	OR EAX,EAX
	JE INIT_IMPORT_TABLE
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_dwOrgChecksum
		CMP EAX,DWORD PTR [EDX]
		JE NotSkipInitIt
			JMP SkipInitIt
NotSkipInitIt:

INIT_IMPORT_TABLE:
	//----- INIT IMPORT TABLE -----
	// 0 - an error occurred
	// 1 - IT initialized successfully
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_IIDInfo
	LEA ESI,[EDX]//ESI -> pointer to the current IID
	//ASSUME ESI : PTR sItInfo

	//----------------------------------------------------------
	//----------------- PREPARE API REDIRECTION ----------------
	//.IF [EBP+PROTECTION_FLAGS]== API_REDIRECT_FLAG
	PUSH EBX
	MOV EBX,EBP
	ADD EBX,OFFSET _RO_PROTECTION_FLAGS
	TEST DWORD PTR [EBX],API_REDIRECT_FLAG
	JZ DonotAPIRedirect
		PUSH ESI
		MOV EBX,EBP
		ADD EBX,OFFSET _RO_Buff
		LEA  EDI,[EBX]
		//ASSUME EDI : PTR sReThunkInfo
		XOR  ECX, ECX
		//.WHILE [ESI].FirstThunk
Kernel32IIDInfoLoop:   
		CMP DWORD PTR DS:[ESI+4],0
		JZ EndOfKernel32IIDInfo
			MOV EDX,DWORD PTR DS:[ESI+4]//[ESI].FirstThunk
			MOV EBX,EBP
			ADD EBX,OFFSET _RO_dwImageBase
			ADD EDX,DWORD PTR [EBX]
Kernel32FunInfoLoop:
			//.WHILE DWORD PTR [EDX]
			CMP DWORD PTR DS:[EDX],0
			JZ EndOfKernel32FuncInfo
				INC ECX
				ADD EDX,4
			JMP Kernel32FunInfoLoop
EndOfKernel32FuncInfo:
			//.ENDW
			ADD ESI,0Ch//SIZEOF sItInfo
		JMP Kernel32IIDInfoLoop
EndOfKernel32IIDInfo:
		//.ENDW

		// allocate memory for the api stubs
		XOR EDX,EDX
		MOV EAX,5//SIZEOF sApiStub
		MUL ECX
		PUSH EAX
		PUSH GMEM_FIXED
		MOV EBX,EBP
		ADD EBX,OFFSET _RO_GlobalAlloc
		CALL [EBX]
		//hglobal=GlobalAlloc(GMEM_FIXED,sApiStub);
		//.IF (hglobal==0)
		OR EAX,EAX// fatal exit
		JNZ DonotDofatalexit
			ADD ESP,4
			POPAD
			RETN
		//.ENDIF
DonotDofatalexit:
		MOV DWORD PTR DS:[EDI],EAX//[EDI].ApiStubMemAddr
		MOV DWORD PTR DS:[EDI+4],EAX//[EDI].pNextStub
		//ASSUME EDI : NOTHING
   		POP  ESI
DonotAPIRedirect:
	//.ENDI
	POP EBX

	// start with the real routine
	//.WHILE [esi].FirstThunk != 0
DllIIDInfoLoop:
	CMP DWORD PTR DS:[ESI+4],0
	JZ EndOfDllIIDInfo;
	   // load the library
		MOV EBX,DWORD PTR DS:[ESI]//[esi].DllNameRVA
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_dwImageBase
		ADD EBX,DWORD PTR [EDX]
		// decrypt dll string
		MOV EAX,EBX	   
		CALL _EnDeCryptString
		MOV EDX,EBP
		ADD EDX,OFFSET InitITContinue1
		LEA EAX, [EDX]// goto InitITContinue1
		PUSH EAX
		RETN
//-------------------------------   
// eax = VA of target string
//DWORD EnDeCryptString(char* Base,DWORD VA)
_EnDeCryptString:
  	PUSH ESI
  	PUSH EDI   		
	MOV ESI,EAX
	MOV EDI,EAX
DllCryptLoop:
		LODS BYTE PTR DS:[ESI]
		ROR AL,4
		STOS BYTE PTR ES:[EDI]
		CMP BYTE PTR DS:[EDI],0
	JNZ DllCryptLoop
	POP EDI
	POP ESI
	RETN	
//End of EnDeCryptString Function
//-------------------------------
InitITContinue1:
		PUSH EBX
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_LoadLibrary
		CALL [EDX]
		//hmodule=LoadLibrary(*(IIDInfo.DllNameRVA+dwImageBase));
		//.IF (hmodule==0) .GOTO SkipInitIt
		TEST EAX,EAX
		JZ SkipInitIt	
		// zero dll name
		PUSH EDX
		PUSH EAX// save dll base
		//----------------------------------------------------------
		//---------------- Delete Import Information ---------------
		//.IF [EBP+PROTECTION_FLAGS]== DESTROY_IMPORT_FLAG
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_PROTECTION_FLAGS
		TEST DWORD PTR [EDX],DESTROY_IMPORT_FLAG
		JZ DontKillDllName
			// push return address
			MOV EDX,EBP
			ADD EDX,OFFSET DontKillDllName
			LEA EAX,[EDX]
			PUSH EAX // push return address :)
			MOV EAX,EBX
			JMP KillString
		//.ENDIF
DontKillDllName:
		POP EBX	// EBX -> library handle
		POP EDX
		// process the (Original-)FirstThunk members
		MOV ECX,DWORD PTR DS:[ESI+8]//[esi].OrgFirstThunk
		//.IF ecx == 0
		OR ECX,ECX
		JNZ OrgFirstThunkNotZero1
			MOV ECX,DWORD PTR DS:[ESI+4]//[esi].FirstThunk
OrgFirstThunkNotZero1:
		//.ENDIF   
		PUSH EBX
		MOV EBX,EBP
		ADD EBX,OFFSET _RO_dwImageBase
		ADD ECX,[EBX]	// ecx -> pointer to current thunk
		MOV EDX,DWORD PTR DS:[ESI+4]//[esi].FirstThunk
		ADD EDX,[EBX]	// edx -> pointer to current thunk (always the non-original one)
		POP EBX
		//.WHILE dword ptr [ecx] != 0
FuncIIDInfoLoop:
		CMP DWORD PTR DS:[ECX],0
		JZ EndOfFuncIIDInfo
			TEST DWORD PTR [ECX],IMAGE_ORDINAL_FLAG32// is it an ordinal import ?
			JNZ __OrdinalImp
	  		// process a name import
				MOV EAX,DWORD PTR [ECX]
				ADD EAX,2
				PUSH EBX
				MOV EBX,EBP
				ADD EBX,OFFSET _RO_dwImageBase
				ADD EAX,[EBX]// eax points now to the Name of the Import
				POP EBX

				PUSH EAX
				CALL _EnDeCryptString
				POP  EAX

				MOV EDI,EAX	// save the API name pointer for destroying it later

				PUSH EDX
				PUSH ECX// save the Thunk pointers

				PUSH EAX
				PUSH EBX
				MOV EDX,EBP
				ADD EDX,OFFSET _RO_GetProcAddress
				CALL [EDX]
				//dw_=GetProcAddress(KernelBase,sz_);

				//.IF eax == NULL
				OR EAX,EAX
				JNZ GetProcAddressNotNULL
					POP ECX
					POP EDX
					JMP SkipInitIt
GetProcAddressNotNULL:
				//.ENDIF
				POP ECX
				POP EDX
				//->kill API name			
				PUSH EDX
  				PUSHAD
				//----------------------------------------------------------
				//---------------- Delete Import Information ---------------
				//.IF [EBP+PROTECTION_FLAGS]== DESTROY_IMPORT_FLAG
				MOV EDX,EBP
				ADD EDX,OFFSET _RO_PROTECTION_FLAGS
				TEST [EDX],DESTROY_IMPORT_FLAG
  				JZ  DontKillApiName
					MOV EDX,EBP
					ADD EDX,OFFSET DontKillApiName
  					LEA EAX, [EDX]	// push return address
  					PUSH EAX
					MOV EAX, EDI
					JMP KillString
DontKillApiName:
				//.ENDIF
				POPAD
				POP EDX
				//-> paste API address
				MOV DWORD PTR [EDX],EAX	   
				JMP __NextThunkPlease

__OrdinalImp:
			// process an ordinal import
			PUSH EDX
			PUSH ECX	// save the thunk pointers
			MOV EAX,DWORD PTR [ECX]
			SUB EAX,080000000h
			PUSH EAX
			PUSH EBX
			MOV EDX,EBP
			ADD EDX,OFFSET _RO_GetProcAddress
			CALL [EDX]
			//dw_=GetProcAddress(KernelBase,sz_);
			TEST EAX,EAX
			JZ SkipInitIt
			POP ECX
			POP EDX
			MOV DWORD PTR [EDX],EAX
__NextThunkPlease:
	 		// eax = Current Api address
   			// ebx = dll base
   			// edx = non-org thunk pointer
			//----------------------------------------------------------
			//----------------- PREPARE API REDIRECTION ----------------
			//.IF [EBP+PROTECTION_FLAGS]== API_REDIRECT_FLAG
			PUSH ECX
			MOV ECX,EBP
			ADD ECX,OFFSET _RO_PROTECTION_FLAGS
			TEST DWORD PTR [ECX],API_REDIRECT_FLAG
			JZ DonotAPIRedirect2
				//.IF [EBP+bNT]
				MOV ECX,EBP
				ADD ECX,OFFSET _RO_bNT
				CMP DWORD PTR [ECX],0
				JZ WindowsNotNT
				//.IF EBX < 070000000h || EBX > 077FFFFFFh
					CMP EBX,070000000h
						JB CHECK_0x70000000
					CMP EBX,077FFFFFFh
						JBE FinishThunkRedDo
CHECK_0x70000000:
						JMP	SkipThunkRed
					JMP FinishThunkRedDo
				//.ENDIF
				//.ELSE
WindowsNotNT:
					//.IF EBX < 080000000h
					CMP EBX,080000000h
					JNB FinishThunkRedDo
						JMP SkipThunkRed
					//.ENDIF
FinishThunkRedDo:
				//.ENDIF
				PUSH EDI
				PUSH ESI
				MOV ECX,EBP
				ADD ECX,OFFSET _RO_Buff
				LEA EDI,[ECX]
				//ASSUME EDI : PTR sReThunkInfo
				MOV ESI,DWORD PTR DS:[EDI+4]//[EDI].pNextStub
   				MOV [EDX],ESI// make the thunk point to stub mem
   				SUB EAX,ESI
   				SUB EAX,5// sizeof E9XXXXXXXX - Jump long
   				MOV BYTE PTR [ESI],0E9h
				MOV DWORD PTR [ESI+1],EAX
				ADD DWORD PTR DS:[EDI+4],5//ADD [EDI].pNextStub,SIZEOF sApiStub
				//ASSUME EDI : NOTHING
				POP ESI
				POP EDI
SkipThunkRed:
DonotAPIRedirect2:
   			//.ENDIF
			POP ECX
   			ADD ECX,4
			ADD EDX,4
			JMP FuncIIDInfoLoop 
EndOfFuncIIDInfo:
		//.ENDW
		ADD ESI,0Ch//SIZEOF sItInfo	 make esi point to the next IID
		JMP DllIIDInfoLoop
EndOfDllIIDInfo:
	//.ENDW
	XOR EAX,EAX
	INC EAX
//------------------------------
SkipInitIt:
	//.IF eax != TRUE
	CMP EAX,1
	JE ERASE_PE_HEADER
		// exit
		POPAD
		RETN
	//.ENDIF
ERASE_PE_HEADER:
	//----- ERASE PE HEADER ------
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_PROTECTION_FLAGS
	TEST DWORD PTR [EDX],ERASE_HEADER_FLAG
  	JZ SkipEraseHeader
		// zero the header
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_dwImageBase
		MOV EDI,DWORD PTR [EDX]
		ADD EDI,DWORD PTR [EDI+03Ch]// edi -> pointer to PE header
		//assume edi : ptr IMAGE_NT_HEADERS
		MOV ESI,DWORD PTR [EDX]
		MOV ECX,DWORD PTR [EDI+0x54]//.OptionalHeader.SizeOfHeaders
		//assume edi : nothing
ZeroMemLoop:
			MOV BYTE PTR [ESI],0
			INC ESI
        LOOP ZeroMemLoop
SkipEraseHeader:

  	//------ CHECK AGAIN LOADER CRC & COMPARE ------
	MOV EDX,EBP
	ADD EDX,OFFSET DepackerCode
  	LEA EAX,DWORD PTR [EDX]
	MOV ECX,OFFSET OEP_JUMP_CODE_START 
	SUB	ECX,OFFSET DepackerCode//ECX->LOADER_CRC_CHECK_SIZE
  	JMP SM10
		INT 09h//DB   0E9h
  	SM10:
  	CALL _GetCheckSum
  	JMP SM11
  		INT 0Ch//DB   0C7h
  	SM11:
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwLoaderCRC
  	MOV EBX,DWORD PTR [EDX]
	XOR EAX,EBX
	//.IF !ZERO?
	JE DECRYPT_ENTRYPOINT
		JMP SM12
		INT 3//DB 2C 
SM12:
		POPAD
		JMP SM13
		INT 3//DB E8
SM13:
		RETN
	//.ENDIF
  	//----- DECRYPT ENTRYPOINT JUMP CODE -----
DECRYPT_ENTRYPOINT:
	MOV EDX,EBP
	ADD EDX,OFFSET OEP_JUMP_CODE_START
  	LEA EDI,[EDX]
  	MOV ESI,EDI
	LEA EDI,[EDX]
	MOV ECX,OFFSET OEP_JUMP_CODE_END
	SUB ECX,OFFSET OEP_JUMP_CODE_START//ECX->CRYPT_OEP_JUMP_SIZE
	XOR EAX,EAX
OepJumpDecryptLoop:
	LODS BYTE PTR DS:[ESI]
   	XOR AL,OEP_JUMP_ENCRYPT_NUM
   	SUB AL,CL
   	ROL AL,2
	STOS BYTE PTR ES:[EDI]
	LOOP OepJumpDecryptLoop
	MOV EDX,EBP
	ADD EDX,OFFSET OEP_JUMP_CODE_START
	LEA EAX,[EDX]
	PUSH EAX
	RET    
	//-----------------------
	INT 3
	INT 3
	INT 3
	INT 3
	//----- JUMP TO OEP -----
OEP_JUMP_CODE_START:
	//----- CHECK FOR DEBUG API's -----
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_szIsDebuggerPresent
	LEA EAX,[EDX]
	PUSH EAX
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwKernelBase
	PUSH [EDX]
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_GetProcAddress
	//dw_=GetProcAddress(KernelBase,szIsDebuggerPresent);
	CALL [EDX]//bool=IsDebuggerPresent(void)
	OR EAX,EAX// API not present on W95
	//.IF !ZERO?
	JE SECOND_SI_CHECK
		CALL EAX
		OR EAX,EAX
		//.IF  !ZERO?
		JE SECOND_SI_CHECK
			POPAD
			RETN
		//.ENDIF
	//.ENDIF
SECOND_SI_CHECK:
	//------ SECOND SI CHECK ------
	// doesn't work on NT
	// install SEH frame
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_PROTECTION_FLAGS
	TEST DWORD PTR [EDX],CHECK_SI_FLAG
	JZ   SkipSICheck2
		MOV EDX,EBP
		ADD EDX,OFFSET _RO_SEH
		LEA ESI,[EDX]
		//ASSUME ESI : PTR sSEH
		MOV EDX,EBP
		ADD EDX,OFFSET SICheck2_SP
		LEA EAX,[EDX]
		MOV DWORD PTR DS:[ESI+8],EAX//[ESI].SaveEip
    	//ASSUME ESI : NOTHING
    	XOR EBX,EBX
		MOV EDX,EBP
		ADD EDX,OFFSET SehHandler2
		LEA EAX,[EDX]
		PUSH EAX
		PUSH FS:[EBX]
		MOV  FS:[EBX], ESP
		MOV  EDI,EBP
		MOV  EAX,04400h
		JMP SM4
		INT 3//DB 0C7h
SM4:
		INT 68h
SICheck2_SP:	
        XOR EBX,EBX
		POP FS:[EBX]
		ADD ESP,4

		//.IF DI == 01297h || DI == 01277h || DI == 01330h
		CMP DI,01297h
		JE SI_DEBUG_EXIST
		CMP DI,01277h
		JE SI_DEBUG_EXIST
		CMP DI,01330h
		JNZ SkipSICheck2
SI_DEBUG_EXIST:
			JMP SM5
			INT 7//DB 0FFh
SM5:	   
			POPAD
			JMP SM6
			INT 1//DB 0E8h
SM6:
			RETN
		//.ENDIF
SkipSICheck2:
	MOV EDX,EBP
	ADD EDX,OFFSET OepJumpCodeCont
	LEA EAX,[EDX]
	PUSH EAX
	RET    
//------------------------------
// ------ OEP SEH HANDLER ------
//SehHandler_OEP_Jump PROC C pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD
SehHandler_OEP_Jump:
	PUSH EBP
	MOV EBP,ESP
	PUSH EDI
	MOV EAX,DWORD PTR SS:[EBP+010h]//pContext
	//ASSUME EAX : PTR CONTEXT

	// restore original seh handle
	MOV EDI,DWORD PTR DS:[EAX+0C4h]	//[EAX].regEsp
	PUSH DWORD PTR DS:[EDI]
	XOR EDI,EDI
	POP DWORD PTR FS:[EDI]

	// kill seh frame
	ADD DWORD PTR DS:[EAX+0C4h],8	//[EAX].regEsp

	// set EIP to the OEP
	MOV EDI,DWORD PTR DS:[EAX+0A4h]//[EAX].regEbx; EDI -> OEP
	ROL EDI,7
	MOV DWORD PTR DS:[EAX+0B8h],EDI//[EAX].regEip

	MOV EAX,0//ExceptionContinueExecution
	//ASSUME EAX : NOTHING
	POP EDI
	LEAVE
	RETN
//SehHandler_OEP_Jump ENDP
//-----------------------------------------
OepJumpCodeCont:
	//---- ZERO THE LOADER CODE AND DATA ----
	XOR AL,AL
	MOV EDX,EBP
	ADD EDX,OFFSET DepackerCode
	LEA EDI,[EDX]
	MOV ECX,OFFSET SehHandler_OEP_Jump
	SUB ECX,OFFSET DepackerCode
LoaderZeroLoop:
		STOS BYTE PTR ES:[EDI]
	LOOP LoaderZeroLoop
	MOV EDX,EBP
	ADD EDX,OFFSET OEP_JUMP_CODE_END
	LEA  EDI,[EDX]
	MOV ECX,OFFSET LOADER_CRYPT_END
	SUB ECX,OFFSET OEP_JUMP_CODE_END
	LoaderVarZeroLoop:
		STOS BYTE PTR ES:[EDI]
	LOOP LoaderVarZeroLoop

	POPAD	// RESTORE STARTUP REGS
			// After this POPAD:
			// EAX - OEP Seh handler
			// EBX - OEP (rored)
	
  	//------ install OEP JUMP SEH frame ------	
	PUSH EAX
	XOR  EAX, EAX
	PUSH DWORD PTR FS:[EAX]
	MOV DWORD PTR FS:[EAX],ESP

	JMP  SM3
	INT 3	//DB 87
SM3: 		// the seh handler will set EIP to the OEP :)

OEP_JUMP_CODE_END:
//----------------------------------------
/*OepJumpCodeCont:
//------ install OEP JUMP SEH frame ------
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwImageBase
	MOV EAX,DWORD PTR [EDX]
	MOV EDX,EBP
	ADD EDX,OFFSET _RO_dwOrgEntryPoint
	ADD EAX,DWORD PTR [EDX]    //MOV EAX,004028EAh
	JMP EAX
	//------------------------------------
OEP_JUMP_CODE_END:*/
//----------------------------------------
	NOP
	INT 3
	INT 3
	INT 3
	INT 3
	//-----------------------
// -------- KILL STRING --------
// EAX = ASCII string address
KillString:
	JMP KillStr2
KillStr1:
		MOV BYTE PTR DS:[EAX],0
		INC EAX
KillStr2:
		CMP BYTE PTR DS:[EAX],0
	JNZ SHORT KillStr1
	RETN
//----------------------------------------------------------------
// ------- SEH HANDLER 1 -------
//SehHandler1 PROC C pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD
SehHandler1:
	PUSH EBP
	MOV EBP,ESP
	PUSH EDI
	MOV EAX,DWORD PTR SS:[EBP+010h]	//pContext
	//ASSUME EAX : PTR CONTEXT
	MOV EDI,DWORD PTR DS:[EAX+09Ch]	//[EAX].regEdi
	MOV EDX,EDI
	ADD EDX,OFFSET _RO_SEH_SaveEip
	PUSH DWORD PTR DS:[EDX]//[EDI+SEH.SaveEip]
	POP DWORD PTR DS:[EAX+0B8h]		//[eax].regEip
	MOV DWORD PTR DS:[EAX+0B4h],EDI	//[eax].regEbp
	MOV DWORD PTR DS:[EAX+0B0h],04h	//[EAX].regEax
	// SI NOT detected !
	MOV EAX,0//ExceptionContinueExecution
	//ASSUME EAX : NOTHING
	POP EDI
	LEAVE
	RETN
//SehHandler1 ENDP
//----------------------------------------------------------------
// ------- SEH HANDLER 2 -------
//SehHandler2 PROC C pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD
SehHandler2:
	PUSH EBP
	MOV EBP,ESP
	PUSH EDI
	MOV EAX,DWORD PTR SS:[EBP+010h]	//pContext
	//ASSUME EAX : PTR CONTEXT
	MOV EDI,DWORD PTR DS:[EAX+09Ch]	//[EAX].regEdi
	MOV EDX,EDI
	ADD EDX,OFFSET _RO_SEH_SaveEip
	PUSH DWORD PTR DS:[EDX]			//[EDI+SEH.SaveEip]
	POP DWORD PTR DS:[EAX+0B8h]		//[eax].regEip
	MOV DWORD PTR DS:[EAX+0B4h],EDI	//[eax].regEbp
	MOV DWORD PTR DS:[EAX+09Ch],0	//[EAX].regEdi
	// SI NOT detected !
	MOV EAX,0	//ExceptionContinueExecution
	//ASSUME EAX : NOTHING
	POP EDI
	LEAVE
	RETN
//SehHandler2 ENDP	
_RO_dwImageBase:	
		INT 3
		INT 3
		INT 3
		INT 3
_RO_dwOrgEntryPoint:
		INT 3
		INT 3
		INT 3
		INT 3
_RO_PROTECTION_FLAGS:
		INT 3
		INT 3
		INT 3
		INT 3
_RO_dwCalcedCRC:
		INT 3
		INT 3
		INT 3
		INT 3
_RO_dwLoaderCRC:
		INT 3
		INT 3
		INT 3
		INT 3
_RO_bNT:
		INT 3
		INT 3
		INT 3
		INT 3
_RO_IIDInfo:
//_RO_IIDInfo0:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo1:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo2:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo3:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo4:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo5:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo6:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo7:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo8:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo9:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo10:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo11:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo12:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo13:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo14:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo15:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo16:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo17:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo18:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo19:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo20:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo21:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo22:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo23:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo24:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo25:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo26:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo27:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo28:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
//_RO_IIDInfo29:
		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3

		INT 3
		INT 3
		INT 3
		INT 3
_RO_SEH:
//_RO_SEH_OrgEsp:
		INT 3
		INT 3
		INT 3
		INT 3
//_RO_SEH_OrgEbp:
		INT 3
		INT 3
		INT 3
		INT 3
_RO_SEH_SaveEip:
		INT 3
		INT 3
		INT 3
		INT 3
_RO_LoadLibrary:
		INT 3
		INT 3
		INT 3
		INT 3
_RO_GetProcAddress:
		INT 3
		INT 3
		INT 3
		INT 3
// some API stuff
_RO_szKernel32:			//db "Kernel32.dll",0,13
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
_RO_dwKernelBase:
		INT 3
		INT 3
		INT 3
		INT 3
_RO_szGetModuleHandle:	//db "GetModuleHandleA",0,17
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
_RO_GetModuleHandle:
		INT 3
		INT 3
		INT 3
		INT 3
_RO_szVirtualProtect:	//db "VirtualProtect",0,15
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
_RO_VirtualProtect:
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_szGetModuleFileName://db "GetModuleFileNameA",0,19
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
_RO_GetModuleFileName:
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_szCreateFile:		//db "CreateFileA",0,12
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_CreateFile:
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_szGlobalAlloc:		//db "GlobalAlloc",0,12
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_GlobalAlloc:
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_szGlobalFree:		//db "GlobalFree",0,11
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
_RO_GlobalFree:
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_szReadFile:			//db "ReadFile",0,9
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_ReadFile:
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_szGetFileSize:		//db "GetFileSize",0,12
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_GetFileSize:
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_szCloseHandle:		//db "CloseHandle",0,12
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_CloseHandle:
		INT 3	
		INT 3	
		INT 3	
		INT 3
_RO_szIsDebuggerPresent://db "IsDebuggerPresent",0,18
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
		INT 3
LOADER_CRYPT_END:

// This variables won't be crypted:
//TlsBackupLabel://IMAGE_TLS_DIRECTORY32 
//_RO_TlsBackup_StartAddressOfRawData:
		INT 3
		INT 3
		INT 3
		INT 3
//_RO_TlsBackup_EndAddressOfRawData:
		INT 3
		INT 3
		INT 3
		INT 3
//_RO_TlsBackup_AddressOfIndex:             // PDWORD
		INT 3
		INT 3
		INT 3
		INT 3
//_RO_TlsBackup_AddressOfCallBacks:         // PIMAGE_TLS_CALLBACK *
		INT 3
		INT 3
		INT 3
		INT 3
//_RO_TlsBackup_SizeOfZeroFill:
		INT 3
		INT 3
		INT 3
		INT 3
//_RO_TlsBackup_Characteristics:
		INT 3
		INT 3
		INT 3
		INT 3

//ChecksumLabel:
_RO_dwOrgChecksum:
		INT 3
		INT 3
		INT 3
		INT 3
_RO_Buff: //buffer for some stuff, its size: 2000h(VS) - DEPACKER_CODE_SIZE
		INT 3
		INT 3
		INT 3
		INT 3
DepackerCodeEND:
	RET
	INC ESP	//'D'
	INC EBP	//'E'
	PUSH EAX//'P'
	INC ECX	//'A'
	INC EBX	//'C'
	DEC EBX	//'K'
	INC EBP	//'E'
	DEC ESI	//'N'
	INC ESP	//'D'
	}
}
