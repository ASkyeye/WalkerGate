# WalkerGate

It's a method to take syscall with memory parsing of ntdll. How it's work ?

In first time, we take the address of NtAccessCheck (First syscall),  NtLoadKey3 (Last syscall) and we take the address of all targeted function with and we can :
- Read the content and take syscall (HellsGate)
- Read the content and take syscall and if it's hook, look higher and/or lower syscall to find no-hook syscall (HalosGate).

But here, we just take the address.

We start parsing a WORD variable at -1, that contain the syscall value
With the address of NtAccessCheck we have the 1st syscall (ID : 0) and we parse all content until NtLoadKey3  (ID : 1D6).
During parsing if we find : 
0x4c, 0x8b 0xd1, 0xb8 // mov r10, rcx | mov eax
0xe9 | jmp

We pass a syscall stub or hook so add +1 to the syscall variable. And when the parser is equal to the function addresse we stop parsing and we return the syscall ID.


