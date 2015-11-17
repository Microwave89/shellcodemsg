#include <Windows.h>


#define STATUS_SERVICE_NOTIFICATION ((NTSTATUS)0x40000018L)
#define NT_SYSCALL_START 0x0	///System call numbers always started with 0.
#define NT_SYSCALL_END 0x1000	///0x1000 is the begin of win32k system calls and hence, the last possible NT syscall is 0xFFF.


typedef LONG NTSTATUS;
typedef NTSTATUS(*PSYSCALL_STUB)(ULONG syscallNr, ...);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef enum _HardErrorResponseOptions {
	ResponseOptionNone = 0,
	ResponseOptionDefaultDesktopOnly = 0x20000,
	ResponseOptionHelp = 0x4000,
	ResponseOptionRightAlign = 0x80000,
	ResponseOptionRightToLeftReading = 0x100000,
	ResponseOptionTopMost = 0x40000,
	ResponseOptionServiceNotification = 0x00200000,
	ResponseOptionServiceNotificationNT3X = 0x00040000,
	ResponseOptionSetForeground = 0x10000,
	ResponseOptionSystemModal = 0x1000,
	ResponseOptionTaskModal = 0x2000,
	ResponseOptionNoFocus = 0x00008000
} HardErrorResponseOptions;

typedef enum _HardErrorResponseIcon {
	IconAsterisk = 0x40,
	IconError = 0x10,
	IconExclamation = 0x30,
	IconHand = 0x10,
	IconInformation = 0x40,
	IconNone = 0,
	IconQuestion = 0x20,
	IconStop = 0x10,
	IconWarning = 0x30,
	IconUserIcon = 0x80
} HardErrorResponseIcon;


void dispMsg(PUNICODE_STRING pText, PUNICODE_STRING pTitle, NTSTATUS status);

#pragma code_seg(".text")
__declspec(allocate(".text")) WCHAR szTitle[] = L"Shellcode =) ";
__declspec(allocate(".text")) WCHAR szText[] = L"Hi from no-ntdll shellcode!";
void mymain(void) {
	UNICODE_STRING uTitle, uText;

	uTitle.Buffer = szTitle;
	uTitle.Length = sizeof(szTitle) - sizeof(UNICODE_NULL);
	uTitle.MaximumLength = sizeof(szTitle);
	uText.Buffer = szText;
	uText.Length = sizeof(szText) - sizeof(UNICODE_NULL);
	uText.MaximumLength = sizeof(szText);

go:
	dispMsg(&uTitle, &uText, STATUS_SERVICE_NOTIFICATION);
	dispMsg(&uText, &uTitle, STATUS_SERVICE_NOTIFICATION);
	dispMsg(NULL, NULL, 0xC0000005);
	goto go;
}


///Uses system call number bruteforcing in order to display a custom message relying neither statically nor dynamically on any library.
#pragma code_seg(".text")
__declspec(allocate(".text")) BYTE syscallStub[] = { 0x89, 0xC8, 0x49, 0x89, 0xD2, 0x4C, 0x89, 0xC2, 0x4D, 0x89, 0xC8, 0x4C, 0x8B, 0x4C, 0x24, 0x28, 0x48, 0x83, 0xC4, 0x08, 0x90, 0x0F, 0x05, 0x48, 0x83, 0xEC, 0x08, 0xC3 };
void dispMsg(PUNICODE_STRING pText, PUNICODE_STRING pTitle, NTSTATUS status) {
	ULONG_PTR dummy;	///With a ULONG_PTR (8 byte on x64 systems) we have more control over the stack.
	UNICODE_STRING uDefault;
	ULONG_PTR params[4];
	ULONG szDefault;	///Forcing the compiler to issue a mov r32, imm32 instruction (5 bytes) instead of doing something
						///more complicated or even access the data section!

	///NtRaiseHardError gets permanently broken for current execution if we attempt to display a service notification
	///with either pText or pTitle being NULL. This is, however, not the case for a status value != STATUS_SERVICE_NOTIFICATION.
	for (ULONG i = NT_SYSCALL_START; i < NT_SYSCALL_END; i++) {
		if (0x4A == i)	///Avast doesn't like this call number on Windows 10...
			continue;

		///We will iterate over a lot of syscalls that have potential to corrupt our stack values due to
		///its return values provided. We are quite safe if we renew everything before trying the next system call.

		///Moreover, we keep as much parameters as possible from having magic values such as "INVALID_HANDLE_VALUE" or "NULL"
		///to not inadvertently run into blocking API calls that succeed with much less parameters (e.g. "NtSuspendThread").
		///That is the reason why we dont call the syscall stub with (i, status, 0, 0, NULL, 0, &harderrResp).
		///Refer to "syscalltest" code for further explanation.
		dummy = 0x1379682497286543;
		uDefault.Length = sizeof(szDefault) - sizeof(UNICODE_NULL);
		uDefault.MaximumLength = sizeof(szDefault);
		*(PULONG)&szDefault = 0x3F;	/// Insert a single "?" char...others are 0.
		uDefault.Buffer = (WCHAR*)&szDefault;

		params[0] = (ULONG_PTR)(pText ? pText : &uDefault);		///Should we fall back to default values?
		params[1] = (ULONG_PTR)(pTitle ? pTitle : &uDefault);
		params[2] = ((ULONG)IconInformation | (ULONG)ResponseOptionSystemModal);
		params[3] = 2000;	///Timeout = 2 s

#pragma warning (push)
#pragma warning (disable:4055)		///Casting syscall stub shellcode "data" pointer into PSYSCALL_STUB typ function pointer
		((PSYSCALL_STUB)syscallStub)(i, status, 4, 0x3, params, 0x5, &dummy);
#pragma warning (pop)
	}
}