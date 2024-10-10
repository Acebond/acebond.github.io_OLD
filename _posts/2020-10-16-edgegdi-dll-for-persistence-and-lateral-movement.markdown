---
layout: post
title: EdgeGdi.dll for Persistence and Lateral Movement
date: '2020-10-16 00:00:00'
img_path: /assets/img/2020-10-16/
categories: ['Red Team', Windows]
tags: []
---

I recently read [https://www.chadduffey.com/windows/release_notes/2020/10/10/edgegdi.html](https://www.chadduffey.com/windows/release_notes/2020/10/10/edgegdi.html) which describes how EdgeGdi.dll can be used for persistence, although with the caveat that “Windows wont tolerate the implementation as described here [linked blog post] over a reboot, it’ll blue screen”.

I decided to take on the challenge of solving the blue screen on reboot issue. I created the DLL as described, placed it into System32 and when I rebooted received the stop code 0xC000007B (see Figure 1). Googling the stop code provided no helpful information.

![Figure 1 - Stop code 0xC000007B](/assets/img/2020-10-16/bsod.png)
_Figure 1 - Stop code 0xC000007B_

I rebooted again, but this time with a Kernel debugger attached and received an error message detailing the issue (see Figure 2). The csrss.exe process was trying to load our persistence DLL which failed the device integrity policy.

![Figure 2 - Code Integrity violation](/assets/img/2020-10-16/windbg.png)
_Figure 2 - Code Integrity violation_

The csrss (Windows subsystem) process is marked signature restricted (Microsoft only) (see Figure 3) and is trying to load the unsigned EdgeGdi.dll which causes a code integrity violation. The process is also marked critical, which means that if it exits for any reasons, the system crashes.

![Figure 3 - CSRSS process mitigation policies](/assets/img/2020-10-16/processhacker.png)
_Figure 3 - CSRSS process mitigation policies_

The only solution is to prevent csrss from loading the unsigned DLL by configuring an Access Control Entry (ACE) to deny SYSTEM access to the EdgeGdi.dll (see Figure 4), which prevents csrss from loading the unsigned DLL, which prevents the system crash.

![Figure 4 - Discretionary Access Control List to for EdgeGdi.dll](/assets/img/2020-10-16/dacl.png)
_Figure 4 - Discretionary Access Control List to for EdgeGdi.dll_

The caveat now being that EdgeGdi.dll cannot be loaded by a SYSTEM process, but it WILL be loaded by processes running with NETWORK SERVICE privileges, which can be trivially escalated to SYSTEM privileges using one of the potato methods, see the Game Over Privileges blog post for more details.

Now EdgeGdi.dll can be used for stealthy, stable persistence, or stealthy lateral movement by dropping it into System32 on another machine as described [here](https://www.mdsec.co.uk/2020/10/i-live-to-move-it-windows-lateral-movement-part-3-dll-hijacking/).

