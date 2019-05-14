
#include "stdafx.h"
#include "AresProtectAsm.h"
#include "commdlg.h"
#include "commctrl.h"
#include "shellapi.h"
#include "PeCodecRoutines.h"
#include "PeCryptography.h"

// Globals
HINSTANCE		hInst; //current instance
OPENFILENAME	ofn;
DWORD			AresProtectionFlags;
BOOL			fStatus;
char			cFname[256];
HDROP			hDrop;
HICON			hIcon;
char			szCurDir[]	=	".";
char			szFilter[]	=	"EXE files (*.exe)|*.exe|All files (*.*)|*.*||";

// Forward declarations of functions included in this code module:
LRESULT CALLBACK	About	(HWND, UINT, WPARAM, LPARAM);
LRESULT				DlgProc	(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	MSG msg;
	hInst = GetModuleHandle(0);
	DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_MAINDLG), 0, (DLGPROC)DlgProc, 0);
	ExitProcess(0);
	return (int)msg.wParam;
}

//  FUNCTION: DlgProc(HWND, unsigned, WORD, LONG)
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
LRESULT DlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	UINT wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;

	switch (uMsg) 
	{
	case WM_INITDIALOG:
		hIcon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_ICON));
		SendMessage(hDlg, WM_SETICON, TRUE, (WPARAM)hIcon);
		// check options
		CheckDlgButton(hDlg, IDC_CHECKHEADERCRC,TRUE);
		CheckDlgButton(hDlg, IDC_DESTROYIMPORT,TRUE);
		CheckDlgButton(hDlg, IDC_ANTIDUMP,TRUE);
		DragAcceptFiles(hDlg, TRUE);
		break;
	case WM_DROPFILES:
		hDrop = HDROP(wParam);
		DragQueryFile(hDrop, 0, cFname, sizeof(cFname));
		DragFinish(hDrop);
		SetDlgItemText(hDlg, IDC_TARGETFILE, cFname);
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam); 
		wmEvent = HIWORD(wParam); 
		// Parse the menu selections
		switch (wmId)
		{
		case IDCLOSE:
			SendMessage(hDlg, WM_CLOSE, NULL, NULL);
			break;
		case IDC_CHOOSEFILE:
			// get a file path
			cFname[0] = 0x00;
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.hwndOwner = GetActiveWindow();
			ofn.lpstrFile = cFname;
			ofn.nMaxFile = sizeof(cFname);
			ofn.lStructSize = sizeof(ofn);
			ofn.lpstrFilter = TEXT("EXE files (*.exe)\0*.exe;All files (*.*)\0*.*\0\0");
			ofn.nFilterIndex = 1; 
			//ofn.lpstrInitialDir=szCurDir;
			ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_LONGNAMES | OFN_HIDEREADONLY;
			fStatus = GetOpenFileName(&ofn);//(LPOPENFILENAME
			if(!fStatus)
				return 0;
			SetDlgItemText(hDlg, IDC_TARGETFILE, cFname);
			break;
		case IDC_CRYPT:
			// ----- was a file selected ? -----
			if(cFname == NULL)
			{
				MessageBox(hDlg, "No file selected!", "ERROR", MB_ICONERROR);
				return 0;
			}
			// ---- build the protection flag -----
			AresProtectionFlags = 0;
			if(IsDlgButtonChecked(hDlg, IDC_SICHECK) == BST_CHECKED)
				AresProtectionFlags = AresProtectionFlags | CHECK_SI_FLAG;
			if(IsDlgButtonChecked(hDlg, IDC_DESTROYIMPORT) == BST_CHECKED)
				AresProtectionFlags = AresProtectionFlags | DESTROY_IMPORT_FLAG;
			if(IsDlgButtonChecked(hDlg, IDC_CHECKHEADERCRC) == BST_CHECKED)
				AresProtectionFlags = AresProtectionFlags | CHECK_HEADER_CRC;
			if(IsDlgButtonChecked(hDlg, IDC_ANTIDUMP) == BST_CHECKED)
				AresProtectionFlags = AresProtectionFlags | ANTI_DUMP_FLAG;
			if(IsDlgButtonChecked(hDlg, IDC_PROCHOLLOW) == BST_CHECKED)
			{
				char szProcessor[] = "PsCreateHollowedProcess.exe";
				char szTemplate[] = "AresProcessTemplate.exe";
				char *szCmd = (char *)malloc(sizeof(szProcessor) + sizeof(szTemplate) + sizeof(cFname) + 7);
				sprintf(szCmd, "%s \"%s\" \"%s\"", szProcessor, szTemplate, cFname);
				//MessageBox(hDlg, szCmd, "TEST", 0);
				system(szCmd);
			}
			else
				CryptFile(cFname, AresProtectionFlags);
			break;
		case IDOK:
			EndDialog(hDlg, 0);
			break;
		case IDC_ABOUT:
			DialogBox(hInst, (LPCTSTR)IDD_ABOUTBOX, hDlg, (DLGPROC)About);
			break;
		}
		break;
	case WM_PAINT:
		hdc = BeginPaint(hDlg, &ps);
		EndPaint(hDlg, &ps);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	case WM_CLOSE:
		EndDialog(hDlg,0);
		break;
	}
	return 0;
}

LRESULT CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
		return TRUE;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) 
		{
			EndDialog(hDlg, LOWORD(wParam));
			return TRUE;
		}
		break;
	}
	return FALSE;
}
