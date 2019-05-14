
#pragma once

#define PROGRESS_MSG	"LWIDMsg"
#define SETSTEP_MSG		0x01
#define SETRANGE_MSG	0x02
#define SETPOS_MSG		0x03

extern UINT WM_PROGRESS_MSG;

void InitRandom();
void EncryptBuffer(char* Base,DWORD dwRV,DWORD Size);
void DecryptBuffer(char* Base,DWORD dwRV,DWORD Size);
void MakePER(char* pEncryptBuff,char* pDecryptBuff,DWORD dwSize);
