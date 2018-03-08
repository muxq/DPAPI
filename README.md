## Windows DPAPI 数据加密保护接口详解
### 什么是DPAPI
DPAPI是Windows系统级对数据进行加解密的一种接口，无需自实现加解密代码，微软已经提供了经过验证的高质量加解密算法，提供了用户态的接口，对密钥的推导，存储，数据加解密实现透明，并提供较高的安全保证。
  
DPAPI提供了两个用户态接口，`CryptProtectData`加密数据，`CryptUnprotectData`解密数据，加密后的数据由应用程序负责安全存储，应用无需解析加密后的数据格式。但是，加密后的数据存储需要一定的机制，因为该数据可以被其他任何进程用来解密，当然`CryptProtectData`也提供了用户输入额外`数据`来参与对用户数据进行加密的参数，但依然无法放于暴力破解。

总体来说，程序可以使用DPAPI来对自己敏感的数据进行加解密，也可持久化存储，程序或系统重启后可解密密文获取原文。如果应用程序，对此敏感数据只是暂存于内存，为了防止被黑客dump内存后进行破解，也对此数据无需进行持久化存储，微软还提供了加解密内存的接口`CryptProtectMemory`和`CryptUnprotectMemory`。加解密内存的接口，并可指定`Flag`对此内存加解密的声明周期做控制，详细见`Memory加密及优缺点`章节。

### DPAPI的会话密钥推导
DPAPI使用的会话密钥由MasterKey和随机数的HASH推导产生，而MasterKey的保护由用户登录密码HASH，随机数，和迭代次数通过可靠的[PBKDF2](https://baike.baidu.com/item/PBKDF2)密钥推导算法生成。其中迭代次数可以修改， `MasterKeyIterationCount` 存储在 `HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\Protect\Providers\GUID` 允许系统管理员增加此迭代计数的密钥中。但是，它不能减少到4000以下。  

为了防止篡改MasterKey，它使用HMAC进行散列。DPAPI再次使用SHA-1作为HMAC和用户的密码来派生HMAC密钥。然后使用来自上面的密码派生加密密钥和Triple-DES来加密MasterKey和MasterKey的HMAC。salt和迭代计数都是非秘密值，因此与加密的MasterKey一起存储，但未加密。这允许DPAPI在给定用户密码的情况下轻松解密MasterKey。

如上图所示，会话密钥的推导使用了MasterKey，随机数，和可选的系统登录密码，用户密码推导生成。16字节的随机数，会以明文的形式存储于加密后的BLOB中，MasterKey是受推导的加密密钥保护。

### DPAPI密钥备份恢复、
恢复密钥是在用户选择从用户的控制面板创建密码重置磁盘（PRD）时生成的。首先，DPAPI生成一个2048位RSA公钥/私钥对，它是恢复密钥。然后使用公钥将当前密码加密并存储在用户的配置文件中，同时将私钥存储到PRD，PRD实际上可以是任何可移动媒体，然后从内存中移除。私钥只存储在PRD中，而其他任何地方都不存在，所以用户将PRD保存在安全的地方非常重要。

如果用户输入错误的密码，Windows会询问他们是否想要使用PRD并重置密码。如果他们选择，运行向导会提示输入新密码，并使用PRD上的私钥解密旧密码并进行更改。
### DPAPI接口调用

- 对数据进行加密：

	```
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	DATA_BLOB BlobKey;
	DataIn.pbData = const_cast<BYTE *>(cbDataIn);    	//明文数据
	DataIn.cbData = nLen;								//明文数据长度
	if(key)
	{
		BlobKey.pbData = const_cast<BYTE *>(key);		//可选用户密码
		BlobKey.cbData = lenKey;						//可选用户密码长度
	}
	CRYPTPROTECT_PROMPTSTRUCT promp;					//是否与用户交互输入可选的用户密码
	promp.cbSize = sizeof(CRYPTPROTECT_PROMPTSTRUCT);
	promp.szPrompt  = L"测试加密";
	promp.dwPromptFlags = CRYPTPROTECT_PROMPT_ON_PROTECT;
	promp.hwndApp = NULL;
	if(!CryptProtectData(&DataIn, L"敏感数据", key ? &BlobKey:NULL, NULL, &promp, 0, &DataOut))
		return false;
	*encLen = DataOut.cbData;
	*encData = malloc(DataOut.cbData);
	memcpy(*encData, DataOut.pbData, DataOut.cbData);	//加密后数据
	LocalFree(DataOut.pbData);	
	```

- 对数据进行解密：

	```
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	DATA_BLOB BlobKey;
	LPWSTR pDescrOut =  NULL;
	if(key)
	{
		BlobKey.pbData = const_cast<BYTE *>(key);		//可选用户密码
		BlobKey.cbData = lenKey;						//可选用户密码长度
	}
	DataIn.pbData = (BYTE *)const_cast<void *>(encData);//待解密数据    
	DataIn.cbData = encLen;								//待解密数据长度

	CRYPTPROTECT_PROMPTSTRUCT promp;					//是否与用户交互输入可选的用户密码
	promp.cbSize = sizeof(CRYPTPROTECT_PROMPTSTRUCT);
	promp.szPrompt  = L"测试解密";
	promp.dwPromptFlags = CRYPTPROTECT_PROMPT_ON_UNPROTECT;
	promp.hwndApp = NULL;

	if (!CryptUnprotectData(&DataIn, &pDescrOut, key ? &BlobKey:NULL, NULL, &promp, 0, &DataOut))
		return false;
	
	*nLen = DataOut.cbData;
	*cbDataIn = malloc(DataOut.cbData);
	memcpy(*cbDataIn, DataOut.pbData, DataOut.cbData);	//解密后的数据明文
	LocalFree(DataOut.pbData);
	```
- 交互弹框提示
	- 加密前提示设置加密等级
	
	- 加密等级分类
	
	- 加密等级设置为高时输入用户密码
	
	- 解密时要求输入用户密码
	
	- 输入错误的用户密码提示
	

### Memory加密及优缺点

`Memory`加解密微软也提供了两个接口，`CryptProtectMemory`内存加密，`CryptUnprotectMemory`内存解密。一般用于即时加解密用户敏感的数据，如用户密码等。内存加解密用于防止他人在您的进程查看敏感信息，如黑客远程dump你的进程内存，分析和破解你的敏感数据。

通常，您使用CryptProtectMemory函数来加密您的进程正在运行时将要解密的敏感信息。请勿使用此功能保存稍后要解密的数据; 如果计算机重新启动，您将无法解密数据。要将加密数据保存到文件以便稍后解密，请使用CryptProtectData函数。

加解密提供了三种标志：

|Flag|说明|
|----|----|
|CRYPTPROTECTMEMORY_SAME_PROCESS|只能在当前进程内加解密，进程重新运行会无法解密|
|CRYPTPROTECTMEMORY_CROSS_PROCESS|可以跨进行加解密，系统重启后失效|
|CRYPTPROTECTMEMORY_SAME_LOGON|使用相同的登录凭据来加密和解密不同进程中的内存，系统重启后失效|

如果需要持存储密文数据，可选用DPAPI的接口。如果临时缓存下敏感数据，可选用对`Memory`加解密的接口。


### 扩展DPAPI加密等级
- 程序内置用户密码  
	应用程序内部可内置用户密码，来持久化加解密敏感的数据。
- 程序使用物理硬件信息作为用户密码  
	应用程序可获取硬件信息如：物理网卡MAC, BIOS UUID等，来持久化加解密敏感的数据。
- 结合PKI技术实现加密用户密码  
	应用程序内置RSA的证书公钥，和私钥加密后的密文，在使用时使用公钥解密数据得到用户密码。
- 或者以上的组合

