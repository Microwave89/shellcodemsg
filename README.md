# shellcodemsg
Displaying a "hard error" messagebox without relying on any library

This project has two goals.
First one is to show how to best create autonomous shellcode using Visual Studio 2015.
The second goal refers to a solution that addresses the problem of sending "signs of life" to the programmer
under extreme circumstances, (e.g. no PEB/TEB available, no ntdll.dll available, ...)

Core concept is the bruteforcing of system calls as already known of "syscalltest" code, as well as the use of NtRaisehardError to display text strings.
As long as the shellcode isn't required to display messages from within cross-session (or service) processes
it doesn't need more than 0.5 KB of RX memory, a stack and a connection to csrss.exe.
If the shellcode is injected or used within processes that have been launched normally (using CreateProcess(Ex)A/W)
this connection is created automatically and the messagebox should pop up.

The shellcode is separated from the data section by using a special Visual C++ command "__declspec(allocate())"
that allows us to place the strings within the .text section. Finally the func_order.txt file will attempt to tell
the linker not to place main() (the OEP) within the code but at the very beginning of .text section (RVA 0x1000). This makes it rather easy to extract and invoke the shellcode afterwards.

In order to obtain the shellcode you can simply compile the entire project with its settings then open the shellcodemsg.exe file with a hex editor and copy 512 bytes starting at file offset 0x400. You can now place the copied bytes at any memory position of a process, which fulfils the restrictions mentioned above, and jump to its beginning. Due to its high-level nature the shellcode does not destroy any registers or the stack so you should be able to continue program execution normally after invoking the shellcode. Note that you can also edit the message strings ;) 
