#include "../git-compat-util.h"
#include "win32.h"
#include <conio.h>
#include "../strbuf.h"
#include "resource.h"

DIR *opendir(const char *name)
{
	int len;
	DIR *p;
	p = (DIR*)malloc(sizeof(DIR));
	memset(p, 0, sizeof(DIR));
	strncpy(p->dd_name, name, PATH_MAX);
	len = strlen(p->dd_name);
	p->dd_name[len] = '/';
	p->dd_name[len+1] = '*';

	if (p == NULL)
		return NULL;

	p->dd_handle = _findfirst(p->dd_name, &p->dd_dta);

	if (p->dd_handle == -1) {
		free(p);
		return NULL;
	}
	return p;
}
int closedir(DIR *dir)
{
	_findclose(dir->dd_handle);
	free(dir);
	return 0;
}


#define PASSWD_MAX 128
static char *g_prompt;
static char g_passwd[PASSWD_MAX];

BOOL CALLBACK passwd_dlg_proc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg == WM_INITDIALOG)
	{
		// Set prompt text
		HWND prompt;
		prompt=GetDlgItem(hwndDlg,IDC_PROMPT);
		SetWindowText(prompt,g_prompt);

		// Make sure edit control has the focus
		if (GetDlgCtrlID((HWND) wParam) != IDC_PASSWORD)
		{ 
			SetFocus(GetDlgItem(hwndDlg, IDC_PASSWORD));
			return FALSE; 
		} 
		return TRUE; 
	}
	else if (uMsg == WM_COMMAND && LOWORD(wParam) == IDCANCEL && HIWORD(wParam) == BN_CLICKED)
	{
		EndDialog(hwndDlg, IDCANCEL);
		return 1;
	}
	else if (uMsg == WM_COMMAND && LOWORD(wParam) == IDOK && HIWORD(wParam) == BN_CLICKED)
	{

		HWND passwd;
		passwd=GetDlgItem(hwndDlg,IDC_PASSWORD);
		GetWindowText(passwd,g_passwd,PASSWD_MAX);
		EndDialog(hwndDlg, IDOK);
		return 1;
	}
	return 0;
}

char *vc_getpass(const char *prompt)
{
	DWORD error=0;
	HINSTANCE hmodule=0;

	hmodule = GetModuleHandle(0);
	g_prompt = prompt;
	memset(g_passwd,0, PASSWD_MAX);
	if( DialogBoxParam(hmodule, MAKEINTRESOURCE(IDD_PASSWORD), 0,
                  (DLGPROC)(passwd_dlg_proc), 0) == IDOK)
		return g_passwd;

	error=GetLastError();

	g_passwd[0] = 0;
	return g_passwd;

}

#include "mingw.c"
