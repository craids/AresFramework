
#pragma once
//---------- OPTIONS MASK ----------
#define CHECK_SI_FLAG			0x01
#define ERASE_HEADER_FLAG		0x02
#define DESTROY_IMPORT_FLAG		0x04
#define CHECK_HEADER_CRC		0x08
#define ANTI_DUMP_FLAG			0x10
#define API_REDIRECT_FLAG		0x20

void CryptFile(char* szFname,DWORD dwProtFlags);
