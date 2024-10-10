---
layout: post
title: Game Over Privileges
date: '2020-05-19 00:00:00'
categories: ['Red Team', Windows]
tags: []
---

On Windows a privilege is the right of an account, such as a user or group account, to perform various system-related operations on the local computer. There are 36 privileges defined in the [Privilege Constants](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants) although a number are used internally by the operating system. There are a number of privileges that are considered game over, in that, if a user gains access to a game over privilege, they effectively have every privilege and can achieve code execution under the NT AUTHORITY\SYSTEM (referred to as SYSTEM) account.

I wanted to discuss privileges from a practical offensive standpoint. These are actually just my notes on privileges made into a blog post because I needed to clean them up.

## Attack 1

If you gain access to (through a misconfiguration, vulnerability in a more privileged process, etc) any of the game over privileges you have completely compromised the local computer.

The privileges SeAssignPrimaryToken, SeCreateToken, SeDebug, SeLoadDriver, SeRestore, SeTakeOwnership and SeTcb are guaranteed to give you SYSTEM. Other privileges could also be abused in specific scenarios and should be investigated.

[https://github.com/gtworek/Priv2Admin/blob/master/README.md](https://github.com/gtworek/Priv2Admin/blob/master/README.md)

## Attack 2

If you are SYSTEM then regardless of the privileges (even if they have been stripped) you have every privilege:

[https://www.tiraniddo.dev/2020/01/dont-use-system-tokens-for-sandboxing.html](https://www.tiraniddo.dev/2020/01/dont-use-system-tokens-for-sandboxing.html)

## Attack 3

Starting with Windows 10 Microsoft have removed SeImpersonate and SeAssignPrimaryToken privileges from service processes when they are not required. Task Scheduler can be leveraged to regain the lost privileges:

[https://itm4n.github.io/localservice-privileges/](https://itm4n.github.io/localservice-privileges/)  
[https://github.com/itm4n/FullPowers](https://github.com/itm4n/FullPowers)

## Attack 4

Often when performing exploits against software running on Windows you will gain code execution within the context of the Local or Network service accounts.

Up until Windows version 1809 (and Server 2019) you could leverage the SeImpersonate or SeAssignPrimaryToken privileges of the service accounts by abusing NTLM local authentication via reflection. This allowed the impersonation or assignment of the SYSTEM token. The most common variations of this method are [HotPotato](https://github.com/foxglovesec/Potato), [RottenPotato](https://github.com/foxglovesec/RottenPotato), [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)and [JuicyPotato](https://github.com/ohpe/juicy-potato).

JuicyPotato is the most modern and used method. There are several implementations of juicy-potato that use reflective DLL injection or are implemented as a .NET assembly to avoid dropping files to disk.

On Windows version 1809 (and Server 2019) and later, Microsoft “fixed” the reflected NTLM authentication abuse that allowed JuicyPotato to function. This sparked new research into escalating privileges or regaining the lost permissions. I’m going to list the new methods and research that now exist.

**#1)** [https://decoder.cloud/2019/12/06/we-thought-they-were-potatoes-but-they-were-beans/](https://decoder.cloud/2019/12/06/we-thought-they-were-potatoes-but-they-were-beans/)  
[https://github.com/antonioCoco/RogueWinRM](https://github.com/antonioCoco/RogueWinRM)  
[https://ethicalchaos.dev/2020/04/13/sweetpotato-local-service-to-system-privesc/](https://ethicalchaos.dev/2020/04/13/sweetpotato-local-service-to-system-privesc/)  
[https://github.com/CCob/SweetPotato](https://github.com/CCob/SweetPotato)

**#2)** [https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html)  
[https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)  
[https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)  
[EDIT] [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)

**#3)** [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)  
[https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

**#4)** [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)  
[https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)

I’ve opted not to go into detail of the methods as all of the write-ups are fantastic and I highly recommend giving them a read. With the number of methods available it would be highly unlikely that the compromise of a service account doesn’t lead to SYSTEM.
