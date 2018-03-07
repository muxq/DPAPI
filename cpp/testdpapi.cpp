// testdpapi.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <Wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

typedef NTSTATUS(*RtlDecryptMemory)(PVOID Memory, ULONG MemoryLength, ULONG OptionFlags);

void DumpHex(const char *desc, const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	if(desc)
		printf("%s:\n", desc);
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

bool EncryptData(const byte *cbDataIn, const int nLen, const byte *key, const int lenKey, void **encData, int *encLen)
{
	if(!cbDataIn || 0 == nLen)
		return false;
	if(*encData)
		free(*encData);
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	DATA_BLOB BlobKey;
	DataIn.pbData = const_cast<BYTE *>(cbDataIn);    
	DataIn.cbData = nLen;
	if(key)
	{
		BlobKey.pbData = const_cast<BYTE *>(key);
		BlobKey.cbData = lenKey;
	}
	CRYPTPROTECT_PROMPTSTRUCT promp;
	promp.cbSize = sizeof(CRYPTPROTECT_PROMPTSTRUCT);
	promp.szPrompt  = L"测试加密";
	promp.dwPromptFlags = CRYPTPROTECT_PROMPT_ON_PROTECT;
	promp.hwndApp = NULL;
	if(!CryptProtectData(&DataIn, L"测试加密", key ? &BlobKey:NULL, NULL, &promp, 0, &DataOut))
		return false;
	*encLen = DataOut.cbData;
	*encData = malloc(DataOut.cbData);
	memcpy(*encData, DataOut.pbData, DataOut.cbData);
	LocalFree(DataOut.pbData);
	return true;
}

bool DecryptData(const void *encData, const int encLen, const byte *key, const int lenKey, void **cbDataIn, int &nLen)
{

	return false;
}

int _tmain(int argc, _TCHAR* argv[])
{
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	BYTE *pbDataInput =(BYTE *)"你好世界!";
	DWORD cbDataInput = strlen((char *)pbDataInput)+1;
	void *pEncrptData = NULL;
	int EncryptLen;
	EncryptData(pbDataInput, cbDataInput, NULL, 0, &pEncrptData, &EncryptLen);

	DATA_BLOB DataVerify;
	LPWSTR pDescrOut =  NULL;
	if (CryptUnprotectData(
		&DataOut,
		&pDescrOut,
		NULL,                 // Optional entropy
		NULL,                 // Reserved
		NULL,                 // Here, the optional 
		// prompt structure is not
		// used.
		0,
		&DataVerify))
	{
		printf("The decrypted data is: %s\n", DataVerify.pbData);
		printf("The description of the data was: %s\n",pDescrOut);
	}

	static const int MAX_ORG_DATA_LEN = 128;
	char *pszOrgData = (char *)malloc(MAX_ORG_DATA_LEN);
	ZeroMemory(pszOrgData, MAX_ORG_DATA_LEN);
	strcpy(pszOrgData, "ni hao shi jie!");
	DWORD dwInData = strlen(pszOrgData) + 1;
	DWORD dwMod = dwInData % CRYPTPROTECTMEMORY_BLOCK_SIZE;
	DWORD dwPlainData = dwInData;
	if(dwMod > 0)
		dwPlainData = dwInData + (CRYPTPROTECTMEMORY_BLOCK_SIZE - dwMod);
	if (!CryptProtectMemory(pszOrgData, dwPlainData, CRYPTPROTECTMEMORY_SAME_PROCESS))
	{
		free(pszOrgData);
		exit(-1);
	}


	//  Call CryptUnprotectMemory to decrypt and use the memory.
	if(!CryptUnprotectMemory(pszOrgData, dwPlainData, CRYPTPROTECTMEMORY_SAME_PROCESS))
	{
		free(pszOrgData);
		exit(-1);
	}
	printf("plain data is %s\n", pszOrgData);
	SecureZeroMemory(pszOrgData, dwPlainData);

	printf("%X", DataOut);
	getchar();
	return 0;
}

