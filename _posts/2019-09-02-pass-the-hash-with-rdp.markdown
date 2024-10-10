---
layout: post
title: Pass-The-Hash with RDP
date: '2019-09-02 00:00:00'
img_path: /assets/img/2019-09-02/
categories: ['Red Team', Windows]
tags: []
---

There seems to be a common misconception that you cannot Pass-The-Hash (a NTLM hash) to create a Remote Desktop Connection to a Windows workstation or server. This is untrue.

Starting with Windows 2012 R2 and Windows 8.1 (although the functionality was [backported](https://support.microsoft.com/en-us/help/2984976/rdp-8-0-update-for-restricted-administration-on-windows-7-or-windows-s) to Windows 7 and Windows Server 2008 R2), Microsoft introduced Restricted Admin mode. Normally when an RDP session is established, the credentials are passed and stored on the remote server. Connections made in Restricted Admin mode won't send the credentials to the remote server. This protects the user if connecting to a endpoint that has been compromised. This also means we can establish an RDP session in Restricted Admin mode using only an NTLM hash for authentication.

The RDP uses NTLM or Kerberos to perform authentication. A plaintext password is only required post-authentication to support the logon session and as such is not required when using Restricted Admin mode. We can use Mimikatz to Pass-The-Hash (actually OverPass-The-Hash) to ourselves, to create an impersonated logon session (with respect to network authentications requests). This logon session can be used to RDP to a remote server using Restricted Admin mode.

![Using Mimikatz PTH to establish an RDP session with only an NTLM hash](/assets/img/2019-09-02/pth_1.png)
_Using Mimikatz PTH to establish an RDP session with only an NTLM hash_

The biggest caveat is that Restricted Admin mode must be enabled on the remote server. This was not default on Windows 10, but will often be enabled on larger organisations to reduce the number of privileged logon session throughout the network. The user must have Administrator privileges on the remote server and not be a member of the Protected Users group, which prevents authentication using NTLM and DES or RC4 encryption types in Kerberos pre-authentication requests.

![Error when Restricted Admin mode is disabled](/assets/img/2019-09-02/image.png)
_Error when Restricted Admin mode is disabled_

I tested the attack with Network Level Authentication (NLA) enabled and disable and it made no difference.
