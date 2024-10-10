---
layout: post
title: Bypassing LSA Protection on Windows 10/11
date: '2020-07-06 00:00:00'
img_path: /assets/img/2020-07-06/
categories: ['Red Team', Windows]
tags: []
---

Starting with Windows 8.1 (and Server 2012 R2) Microsoft introduced a feature termed LSA Protection. This feature is based on the Protected Process Light (PPL) technology which is a defense-in-depth security feature that is designed to “prevent non-administrative non-PPL processes from accessing or tampering with code and data in a PPL process via open process functions”.

I’ve noticed there is a common misconception that LSA Protection prevents attacks that leverage SeDebug or Administrative privileges to extract credential material from memory, like Mimikatz. LSA Protection does NOT protect from these attacks, at best it makes them slightly more difficult as an extra step needs to be performed.

To bypass LSA Protection you have a few options:

1. Remove the RunAsPPL registry key and reboot (probably the worst method since you’ll lose any credentials in memory)
2. Disable PPL flags on the LSASS process by patching the EPROCESS kernel structure
3. Read the LSASS process memory contents directly instead of using the open process functions

The latter 2 methods require the ability to read and write kernel memory. The easiest method to achieve this will be through loading a driver, although you can create your own I’ve decided to leverage the RTCore64.sys driver from the product [MSI Afterburner](https://www.guru3d.com/files-details/msi-afterburner-beta-download.html). I chose this driver because it's signed and allows reading and writing arbitrary memory, thanks MSI.

I decided to implement the 2nd method since removing the PPL flags allows the usage of already established tools like Mimikatz to dump the credential material from LSASS. To do this we need to find the address of the LSASS EPROCESS structure and patch the 5 values: SignatureLevel, SectionSignatureLevel, Type, Audit, and Signer to zero.

The [EnumDeviceDrivers](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers?redirectedfrom=MSDN) function can be used to leak the kernel base address. This can be used to locate the PsInitialSystemProcess which points to the EPROCESS structure for the system process. Since the kernel stores processes in a linked list, the ActiveProcessLinks member of the EPROCESS structure can be used to iterate the linked list and find LSASS.

![Figure 1 - Code to find the LSASS EPROCESS structure](code.png)
_Figure 1 - Code to find the LSASS EPROCESS structure_

If we look at the EPROCESS structure (see Figure 2 below) we can see that the 5 fields we need to patch are all conventionally aligned into a continuous 4bytes. This lets us patch the EPROCESS structure in a single 4 byte write like so:

> WriteMemoryPrimitive(Device, 4, CurrentProcessAddress + SignatureLevelOffset, 0x00);

![Figure 2 - EPROCESS structure offsets on Windows 1909](EPROCESS3.png)
_Figure 2 - EPROCESS structure offsets on Windows 1909_

Now that the PPL has been removed, all the traditional methods of dumping LSASS will work, such as MimiKatz, the MiniDumpWriteDump API call, etc.

{% include embed/youtube.html id='w2_KqnhgN94' %}

The tool which is written in C/C++ to perform this attack can be found on [GitHub](https://github.com/RedCursorSecurityConsulting/PPLKiller). I’ve only tested on Windows 1903, 1909 and 2004. It should work on all versions of Windows since the feature was introduced but I’ve only got the offsets for those versions implemented.
