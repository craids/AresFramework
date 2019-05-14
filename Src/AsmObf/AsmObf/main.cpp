#include<stdio.h> 
#include<windows.h>
#include<ctime>
#include<tchar.h>
#include<string>
#include<sstream>
#include<fstream>
#include<iomanip>
#include<iostream>
#include<cstdlib>
#include "distorm.h"

using namespace std;

#define MAX_INSTRUCTIONS (1000)

static const char alphanum[] =
"0123456789"
"!@#$%^&*"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz";

void Disassemble(LPCWSTR filename, int codeadd, int rawpointer, string newadd)
{
	stringstream ss;
	ofstream outFile("C:\\temp\\codedump.txt");
    unsigned long dver = 0;
    _DecodeResult res;
    _DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
    unsigned int decodedInstructionsCount = 0, i, next;
    _DecodeType dt = Decode32Bits;
    _OffsetType offset = 0;
    char* errch = NULL;
    int param = 1;
	HANDLE file;
    DWORD filesize, bytesread;
    unsigned char *buf, *buf2;
    dver = distorm_version();

    file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		printf("Could not open file %s (error %d)\n", filename, GetLastError());
	if ((filesize = GetFileSize(file, NULL)) < 0) {
		printf("Error getting filesize (error %d)\n", GetLastError());
		CloseHandle(file);
	}
	buf2 = buf = (unsigned char*)malloc(filesize);
	if (!ReadFile(file, buf, filesize, &bytesread, NULL)) {
		printf("Error reading file (error %d)\n", GetLastError());
		CloseHandle(file);
		free(buf);
	}
	if (filesize != bytesread) {
		printf("Internal read-error in system\n");
		CloseHandle(file);
		free(buf);
	}

    CloseHandle(file);

	while (1) {
        res = distorm_decode(offset, (const unsigned char*)buf, filesize, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
        if (res == DECRES_INPUTERR) {
			printf("Input error, halting!");
			free(buf2);
        }

        for (i = 0; i < decodedInstructionsCount; i++)
			ss << hex << (decodedInstructions[i].offset + codeadd - rawpointer) << " " << decodedInstructions[i].size << " " << (char*)decodedInstructions[i].instructionHex.p << "\n";

        if (res == DECRES_SUCCESS)
			break;
        else if (decodedInstructionsCount == 0)
			break;
        next = (unsigned long)(decodedInstructions[decodedInstructionsCount-1].offset - offset);
        next += decodedInstructions[decodedInstructionsCount-1].size;
        buf += next;
        filesize -= next;
        offset += next;
        }
		outFile << ss.str();
        free(buf2);

}
void HexDump(char * p ,int size,int secAddress)
{
    int i=1,temp=0;
    wchar_t buf[18];      //Buffer  to store the character dump displayed at the right side 
    printf("\n\n%x: |",secAddress);

    buf[temp]    = ' ' ;  //initial space
    buf[temp+16] = ' ' ;  //final space 
    buf[temp+17] =  0  ;  //End of buf
    temp++;               //temp = 1;
    for( ; i <= size ; i++, p++,temp++)
    {
        buf[temp] = !iswcntrl((*p)&0xff)? (*p)&0xff :'.';
        printf("%-3.2x",(*p)&0xff );

        if(i%16 == 0){    //print the chracter dump to the right    
            _putws(buf);
            if(i+1<=size)printf("%x: ",secAddress+=16);
            temp=0;
        }
        if(i%4==0)printf("|");
    }
    if(i%16!=0){
        buf[temp]=0;
        for(;i%16!=0;i++)
            printf("%-3.2c",' ');
        _putws(buf);
    }
}
string obfstr(string oldstr)
{
	string newstr;
	int stringLength = sizeof(alphanum) - 1;
	srand(time(0));
	for (int i = 0; i < oldstr.length(); i++)
		newstr += alphanum[rand() % stringLength];
	return newstr;
}
void Assemble(string address, int rawadd, string ret, string oldstr,int codeadd,int rawpointer, char* src, char* dest)
{
	ifstream inFile, exeFile;
	ofstream oexeFile(dest,ofstream::binary);
	stringstream ss, rdt;
	int rva, numbyte;
	string line, temp, opcode, newstr = obfstr(oldstr);
	string add = address.substr(4,2) + address.substr(2,2) + address.substr(0,2) + "00";
	inFile.open("C:\\temp\\codedump.txt");
	size_t index = ret.find(':');
	string datrva = ret.substr(0,index);
	string rawdat = ret.substr(index + 1, ret.length() - index - 1);
	rdt << rawdat;
	int rawdatadd;
	rdt >> hex >> rawdatadd;
	while(getline(inFile, temp))
		if (temp.find(add) != string::npos)
		{
			line = temp;
			break;
		}
	ss << hex << line.substr(0,6);
	ss >> rva;
	numbyte = atoi(line.substr(7,1).c_str());
	opcode = line.substr(9,line.length()-9);

	string execontent, execontent2;
	exeFile.open(src,ifstream::binary);
	exeFile.seekg (0, exeFile.end);
	int length = exeFile.tellg(),count=0;
	exeFile.seekg (0, exeFile.beg);
	char * buffer = new char [length];
	char * buffer2 = new char [length];
	exeFile.read(buffer,length);
	for(int i=0;i<length;i++)
	{
		if(i+1 != length && buffer[i+1] != 10)
		{
			buffer2[count] = buffer[i];
			count++;
		}
		else if(i+1 == length)
		{
			buffer2[count] = buffer[i];
			count++;
		}
	}
	for(int i=0;i<newstr.length();i++)
	{
		buffer[rawadd+i] = newstr[i];
		buffer[rawdatadd+2+i] = oldstr[i];
	}
	int trva = rva - codeadd + rawpointer;
	stringstream srva, rrva;
	srva << hex << trva;
	int x = 0, y = 0;
	string newopcode = "";
	string newopadd = datrva.substr(4,2) + datrva.substr(2,2) + datrva.substr(0,2) + "00";
	for(int i=0;i<opcode.length()/2;i++)
	{
		if(i >= opcode.length()/2 - 4)
		{
			newopcode += newopadd.substr(x,2);
			x+=2;
		}
		else
		{
			newopcode += opcode.substr(y,2);
			y+=2;
		}
	}
	x = 0;
	for(int i=0;i<(newopcode.length()/2);i++)
	{
		char c;
		stringstream tbuf;
		int ibuf;
		tbuf << newopcode.substr(x, 2);
		tbuf >> hex >> ibuf;
		c = ibuf;
		buffer[trva+i] = c;
		tbuf.str(string());
		x+=2;
	}
	exeFile.close();
	oexeFile.write(buffer,length);
	oexeFile.close();
	inFile.close();
	remove("C:\\temp\\codedump.txt");
	remove("C:\\temp\\idata.txt");
	remove("C:\\temp\\rdata.txt");
}
string DataDump(char * p ,int size,int secAddress,char * target,int rawdat)
{
	int count, i = 1, j=0, temp=0,isa = secAddress, rawadd;
	bool notfound = true;
	stringstream ss, t, b,address, ret;
	string tempstr,btarget(target), ctarget="";
	ifstream inFile, exeFile;
	ofstream outFile("C:\\temp\\idata.txt");
    wchar_t buf[18];
	
	for(int i=0; i<btarget.length() + 100; i++)
		ctarget += "00 ";
	ss << hex << secAddress << ":";

    buf[temp]    = ' ' ;  //initial space
    buf[temp+16] = ' ' ;  //final space 
    buf[temp+17] =  0  ;  //End of buf
    temp++;               //temp = 1;
    for( ; i <= size ; i++, p++,temp++)
    {
        buf[temp] = !iswcntrl((*p)&0xff)? (*p)&0xff :'.';
		b.put(buf[temp]);
		t << hex << ((*p)&0xff);
		if (t.str().length() == 1)
			ss << "0";
		t.str(string());
		ss << hex << ((*p)&0xff) << " ";

        if(i%16 == 0)
		{
			ss << b.str() << endl;
			b.str(string());
            if(i+1<=size)
				ss << hex << (secAddress+=16) << ":";
            temp=0;
        }
    }
	outFile << ss.str();
	outFile.close();

	inFile.open("C:\\temp\\idata.txt");
	count = (ctarget.length() - 2) / 16 + 2;
	stringstream add, t1, t2, str;
	while(!inFile.eof() && notfound)
	{
		int x;
		size_t found;
		getline(inFile,tempstr);
		add << tempstr.substr(0,6);
		if(j > count)
		{
			x += 16;
			t2 << t1.str().substr(48,t1.str().length()-48);
			t1.str(string());
			t1 << t2.str() << tempstr.substr(7,48);
			found = t1.str().find(ctarget);
			if(found!=string::npos)
			{
				//cout << "\nEmpty sled found at offset: " << hex << x << endl;
				//cout << "Index: " << (found/3) << endl;
				x += found/3;
				//cout << "RVA: " << hex << x << endl;
				ret << hex << (x+2);
				rawadd = x - isa + rawdat;
				//cout << "Raw Address: " << hex << rawadd << endl;
				notfound = false;
				address << hex << x;
				ret << ":" << hex << rawadd;
			}
		}
		else if(j == count)
		{
			found = t1.str().find(ctarget);
			if(found!=string::npos)
			{
				//cout << "\nEmpty sled found at offset: " << hex << x << endl;
				//cout << "Index: " << (found/3) << endl;
				x += found/3;
				//cout << "RVA: " << hex << x << endl;
				ret << hex << (x+2);
				rawadd = x - isa + rawdat;
				//cout << "Raw Address: " << hex << rawadd << endl;
				notfound = false;
				address << hex << x;
				ret << ":" << hex << rawadd;
			}
			x += 16;
		}
		else
		{
			if(j == 0)
				add >> hex >> x;
			t1 << tempstr.substr(7,48);
		}
		j++;
		t2.str(string());
		add.str(string());
	}

	return ret.str();
}
void StringDump(char * p ,int size,int secAddress,char * target,int rawdat, string ret, int codeadd, int rawpointer, char* src, char* dest)
{
	int count, i = 1, j=0, temp=0,isa = secAddress, rawadd;
	bool notfound = true;
	stringstream ss, t, b,address;
	string tempstr,ctarget(target);
	ifstream inFile, exeFile;
	ofstream outFile("C:\\temp\\rdata.txt");
    wchar_t buf[18];
	ss << hex << secAddress << ":";

    buf[temp]    = ' ' ;  //initial space
    buf[temp+16] = ' ' ;  //final space 
    buf[temp+17] =  0  ;  //End of buf
    temp++;               //temp = 1;
    for( ; i <= size ; i++, p++,temp++)
    {
        buf[temp] = !iswcntrl((*p)&0xff)? (*p)&0xff :'.';
		b.put(buf[temp]);
		t << hex << ((*p)&0xff);
		if (t.str().length() == 1)
			ss << "0";
		t.str(string());
		ss << hex << ((*p)&0xff) << " ";

        if(i%16 == 0)
		{
			ss << b.str() << endl;
			b.str(string());
            if(i+1<=size)
				ss << hex << (secAddress+=16) << ":";
            temp=0;
        }
    }
	outFile << ss.str();
	outFile.close();
	inFile.open("C:\\temp\\rdata.txt");
	count = (ctarget.length() - 2) / 16 + 2;
	stringstream add, t1, t2, str;
	while(!inFile.eof() && notfound)
	{
		int x;
		size_t found;
		getline(inFile,tempstr);
		add << tempstr.substr(0,6);
		if(j > count)
		{
			x += 16;
			t2 << t1.str().substr(16,t1.str().length()-16);
			t1.str(string());
			t1 << t2.str() << tempstr.substr(tempstr.length()-16,16);
			found = t1.str().find(ctarget);
			if(found!=string::npos)
			{
				//cout << "\nFound at offset: " << hex << x << endl;
				//cout << "Index: " << found << endl;
				x += found;
				//cout << "RVA: " << hex << x << endl;
				rawadd = x - isa + rawdat;
				//cout << "Raw Address: " << hex << rawadd << endl;
				notfound = false;
				address << hex << x;
			}
		}
		else if(j == count)
		{
			x += 16;
			found = t1.str().find(ctarget);
			if(found!=string::npos)
			{
				//cout << "\nFound at offset: " << hex << x << endl;
				//cout << "Index: " << found << endl;
				x += found;
				//cout << "RVA: " << hex << x << endl;
				rawadd = x - isa + rawdat;
				//cout << "Raw Address: " << hex << rawadd << endl;
				notfound = false;
				address << hex << x;
			}
		}
		else
		{
			if(j == 0)
				add >> hex >> x;
			t1 << tempstr.substr(tempstr.length()-16,16);
		}
		j++;
		t2.str(string());
		add.str(string());
	}
	inFile.close();
	if(notfound == false)
		Assemble(address.str(), rawadd, ret, ctarget, codeadd, rawpointer, src, dest);
}

void main(int argc , char ** argv){

    int i=0;
    HANDLE hMapObject,hFile;            //File Mapping Object
    LPVOID lpBase;                      //Pointer to the base memory of mapped file
    PIMAGE_DOS_HEADER dosHeader;        //Pointer to DOS Header
    PIMAGE_NT_HEADERS ntHeader;         //Pointer to NT Header
    IMAGE_FILE_HEADER header;           //Pointer to image file header of NT Header 
    IMAGE_OPTIONAL_HEADER opHeader;     //Optional Header of PE files present in NT Header structure
    PIMAGE_SECTION_HEADER pSecHeader, rdata, idata, text;   //Section Header or Section Table Header
    if(/*argc > */true){

        //Open the Exe File 
		wchar_t wtext[20];
		char*p = argv[1];
		mbstowcs(wtext, p, strlen(p)+1);//Plus nul
		LPWSTR ptr = wtext;
        hFile = CreateFile(ptr,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        if(hFile == INVALID_HANDLE_VALUE){printf("\nERROR : Could not open the file specified\n");};
		
        //Mapping Given EXE file to Memory
        hMapObject = CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,NULL);
        lpBase = MapViewOfFile(hMapObject,FILE_MAP_READ,0,0,0);

        //Get the DOS Header Base 
        dosHeader = (PIMAGE_DOS_HEADER)lpBase;// 0x04000000

        //Offset of NT Header is found at 0x3c location in DOS header specified by e_lfanew
        //Get the Base of NT Header(PE Header)  = dosHeader + RVA address of PE header
        ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader) + (dosHeader->e_lfanew));
        //Identify for valid PE file  
        if(ntHeader->Signature == IMAGE_NT_SIGNATURE){
            //Get the IMAGE FILE HEADER Structure
            header = ntHeader->FileHeader;
            //Info about Optional Header
            opHeader = ntHeader->OptionalHeader;

            //Retrive a pointer to First Section Header(or Section Table Entry)
			int codeadd;
			char * target = argv[3];
            for(pSecHeader = IMAGE_FIRST_SECTION(ntHeader),i=0;i<ntHeader->FileHeader.NumberOfSections;i++,pSecHeader++){
				string s;
				s.append(reinterpret_cast<const char*>(pSecHeader->Name));
				if(!strcmpi(s.c_str(),".rdata"))
					rdata = pSecHeader;
				else if(!strcmpi(s.c_str(),".text"))
				{
					codeadd = opHeader.ImageBase + pSecHeader->VirtualAddress;
					text = pSecHeader;
				}
				else if(!strcmpi(s.c_str(),".idata"))
					idata = pSecHeader;
			}
			string newadd = DataDump((char *)((DWORD)dosHeader + idata->PointerToRawData) , idata->SizeOfRawData , opHeader.ImageBase + idata->VirtualAddress, target, idata->PointerToRawData);
			Disassemble(ptr, codeadd, text->PointerToRawData, newadd);
			StringDump((char *)((DWORD)dosHeader + rdata->PointerToRawData) , rdata->SizeOfRawData , opHeader.ImageBase + rdata->VirtualAddress, target, rdata->PointerToRawData, newadd, codeadd, text->PointerToRawData, argv[1], argv[2]);
        }
        else goto end;

end:
        //UnMaping 
        UnmapViewOfFile(lpBase);
        CloseHandle(hMapObject);
    }
}