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
