---
layout: post
title: 'Capturing and Relaying NTLM Authentication: Methods and Techniques'
date: '2020-05-18 00:00:00'
img_path: /assets/img/2020-05-18/
categories: ['Red Team', Windows]
tags: []
---

This blog post will provide an overview of the methods available to force NTLM authentication to a rogue server, and capture or relay the credential material. These attacks can be leveraged to escalate privileges within an Active Directory domain environment. I like to look at these attacks as having 3 stages which are:

1. Positioning a rogue authentication server so that it is accessible by the victims’ endpoint;
2. Persuading the victim user or OS into authenticating to the rogue server; and lastly
3. Relaying or cracking the obtained credential material.

## Stage 1: The Rogue Server

The rogue authentication server can be a compromised endpoint, network implant or Internet based server. This will largely depend on the type of engagement (Red Team, Internal Penetration Test, Phishing, etc) and your current privileges within the network.

Generally speaking, a network implant (which could just be your laptop) will be the easiest and most flexible option. A compromised endpoint will mean dealing with the local firewall and antivirus, however this rarely prevents the attack, but will create extra caveats. An Internet based server will only work if SMB and/or WebDAV outbound is allowed, and will often limit relay options.

There are 4 open source tools that can be used to create a rogue authentication server. These are:

- [https://github.com/lgandx/Responder](https://github.com/lgandx/Responder)
- [https://github.com/SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket)
- [https://github.com/Kevin-Robertson/Inveigh](https://github.com/Kevin-Robertson/Inveigh)
- [https://github.com/Kevin-Robertson/InveighZero](https://github.com/Kevin-Robertson/InveighZero)

Responder and Impact (specifically the ntlmrelayx script) are written in Python and work best on Linux, Inveigh is written in PowerShell and designed for Windows hosts, InveighZero is written in C# and also designed for Windows hosts. These tools are all parts of toolkits that provide more features than just a rogue authentication server, and I’ll discuss these features in the following sections.

## Stage 2: Coerced Authentication

This is the hardest part of the attack, and can often require a good level of creativity. The objective is to coerce a user or machine into authenticating to the rogue authentication server using [NTLM authentication](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4), which fortunately for us, is supported by a large number of common protocols (such as SMB, HTTP, RDP, LDAP, etc). The most popular method would be LLMNR/NBN-NS/mDNS poisoning, which I’ll discuss first, but there are an array of good options available.

Link Local Multicast Name Resolution (LLMNR), NetBIOS Name Service (NBT-NS) and Multicast DNS (mDNS) are name resolution services that are built into Windows and enabled by default. LLMNR/NBN-NS/mDNS poisoning attacks leverages the fact that Windows will assume everyone on the network is trusted to answer queries. This allows an attacker to respond to legitimate hostname queries with the rogue authentication server IP address. Since Windows is generally performing name resolution with the intent of connecting to the server, this causes machines throughout the network to authenticate to the rogue server. All the tools mentioned above expect Impact have name spoofing capabilities built-in.

The same principle discussed in the above name resolution attacks apply to the link layer Address Resolution Protocol (ARP). ARP poisoning can be leveraged to convince targeted victims into thinking that the rogue server is actually the file server, or Domain Controller or any legitimate server that already exists within the network. This can lead to the victim authenticating to the rogue server instead of the legitimate server it initially intended on communicating with.

There are a number of file types that when parsed by Windows Explorer, will cause the download of a remote resource. This remote recourse can be a file that requires NTLM authentication, which Windows will perform automatically and without user interaction. These files types are [SCF](https://room362.com/post/2016/smb-http-auth-capture-via-scf/), [LNK and URL](https://goblinsecurity.blogspot.com/2017/08/back-and-forth-with-lnk-and-netntlm.html). By putting these files into a network share, with a filename that causes them to be displayed at the top of the directory listing for added effect, visitors will automatically authenticate to the rogue server. Mileage may vary as Windows 10 seems to have removed this “feature” for at the very least SCF files.

Phishing or backdooring files for NTLM authentication is another common method. [PDF](https://github.com/3gstudent/Worse-PDF), [Microsoft Word](https://twitter.com/PythonResponder/status/1161338972955697152) and [Microsoft Access](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/unc-path-injection-with-microsoft-access/) files can be crafted to cause an NTLM authentication request when opened. These filetypes all supported embedding external content that will be automatically fetched by the respective program. An attacker can leverage this functionality to coerce authenticate requests. I doubt that list is exhaustive and encourage you to research the types of files used on the network for UNC path injection positions.

Security researchers have discovered vulnerabilities within Microsoft software that allows an attacker to force a target machine into performing NTLM authentication with an arbitrary host. The [SpoolSample](https://github.com/leechristensen/SpoolSample) vulnerability by Lee Christensen uses the Print System Remote Protocol (MS-RPRN) interface to requests that a server send updates to an arbitrary host regarding the status of print jobs. This can be used to coerce any machine running the service into authenticating to any machine. This method is so powerful, it can be leveraged to move laterally through Active DIrectory forests.

A ZDI researcher discovered the ability to request Exchange to authenticate to an arbitrary URL over HTTP via the Exchange PushSubscription feature. This attack was called [PowerPriv](https://github.com/G0ldenGunSec/PowerPriv)and could often be used to escalate to Domain Admin given the excessive privileges held by the Exchange servers group. Both of these issues were initially considered intended behaviour by Microsoft but later patched due to the security consequences. However, I still come across vulnerable Windows and Exchange servers on internal networks so these methods remain very useful.

There are a few MS-SQL stored procedures that can be leveraged for NTLM authentication. These can be useful when you have the ability to execute SQL queries on an MS-SQL server through compromised credentials, privilege misconfigurations, or an SQL injection vulnerability. The stored procedures [xp\_dirtree and xp\_fileexist](https://github.com/NetSPI/PowerUpSQL/wiki/Audit-Functions) can be used with a UNC path to cause the SQL service account to perform an SMB connection and NTLM authentication request.

Stale Network Address Configurations (SNACs) are misconfigurations whereby a server is trying to connect to an IP address that no longer exists within the network. IP aliasing can be used to assign the stale IP address to a network interface on an attacker controlled device to receive the traffic from the misconfigured server. One of the possible outcomes is that the server will connect using a protocol that supports NTLM authentication, and respond to authentication requirements. The tool [Eavesarp](https://github.com/arch4ngel/eavesarp) can help discover these misconfigurations.

By default Windows has IPv6 enabled, and will periodically request an IPv6 address using DHCPv6. If IPv6 is not used within the internal network, and IPv6 has not been disabled, then an attacker can [stand-up a DHCPv6 server](https://github.com/fox-it/mitm6). The malicious DHCPv6 server can be used to assign link-local IPv6 address and configure the default DNS server. Since IPv6 takes precedence over IPv4, the attacker now controls DNS lookups and can selectively poison queries to force the victims into connecting to a rogue authentication server.

## Stage 3.1 : Cracking the Hash

This section requires understanding the basics of the NTLM authentication protocol. NTLM authentication is a challenge-response protocol, whereby a client connecting to a server will be presented with a challenge (in NTLMv1 this would be an 8-byte random number), the client must encrypt the challenge value with their NTLM password hash and return this value to the server for verification. The server is then responsible for validating the encrypted value using its local Security Account Manager (SAM) database or with the help of a Domain Controller. The validation is performed by performing the same encryption operation and checking if the client was correct.

In the event a client performs NTLM authentication with a rogue authentication server, the same process described above takes place. This allows the attacker to obtain a value encrypted with the NTLM hash of the user who authenticated. This key material is an effective hash that can be brute forced to disclose the users plaintext password.

The brute force process reads a password from a wordlist, converts it to an NTLM hash, encrypts the challenge with the NTLM hash (creating a challenge response) and checks if it matches the challenge response received from the victim to determine if the guessed password is correct.

The attacker can control the challenge, which does allow the use of rainbow tables (precomputed lookup tables), but this only works for the older NTLMv1 protocol. In the NTLMv2 implementation, the client chooses part of the challenge which mitigates rainbow table attacks.

## Stage 3.2: Relaying the Hash

Since the attacker can choose the challenge, nothing prevents the attacker from retrieving a challenge from a service within the network and having the victim solve it. This allows the attacker to authenticate to an arbitrary service within the network as the victim.

![](/assets/img/2020-05-18/image.png)

Depending on the victim privileges, this can be leveraged to further compromise machines within the network, gain access to file servers, update Active Directory objects on the Domain Controller, etc.

The advantage of relying is that the credential material never has to be cracked, although you can still perform a brute force to recover the plaintext password as described in 3.1. The only downside is the additional time required to set up the relay server and select appropriate relay targets.

This can be done using Impacket ntlmrelayx, Inveigh-Relay or Responder MultiRelay.

## Recommendations and Mitigations

The absolute best solution would be to configure the security policy **Network Security: Restrict NTLM: Outgoing NTLM traffic to remote servers** to **Deny all**. This will prevent the device from using NTLM authentication, and consequently force the use of Kerberos authentication, which is the preferred authentication protocol within an Active Directory network. Any legacy systems that require NTLM authentication should be added to the security policy **Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication**.

![Example Secure Configuration (NTLM authentication can only be performed to a single legacy system)](/assets/img/2020-05-18/image-1.png)
_Example Secure Configuration (NTLM authentication can only be performed to a single legacy system)_

The below recommendations and mitigations are grouped into the 3 phases of the attack, and can be used to improve the security posture of the network. However, even if all the below recommendations and mitigations are applied, some methods such as backdoored or malicious files within a network share will continue to be effective unless the above security policies are configured.

### Stage 1: The Rogue Server

- Use MAC address filtering or port security to prevent rogue devices connecting to the network.
- Ensure device isolation on guest, public and BYOD networks. 
- Ensure adequate endpoint protections and hardening best practices are applied to prevent a compromise in the initial instance.
- Block SMB outbound to the Internet.
- Disable the WebClient service (which is WebDAV) to prevent fallback attacks. SMB will fallback to WebDAV which uses HTTP(S) on Windows.

### Stage 2: Coerced Authentication

- Patch operating systems
- Disable LLMNR and NBT-NS
- Disable WebDAV on all endpoints
- Ensure ARP packets are validated against an authoritative source such as the DHCP lease reservations
- Ensure there are no stale network address configurations
- Ensure file shares follow the principle of least privilege
- Ensure reasonable and logical network segregation
- Setup a honeypot that broadcasts fake LLMNR and NBT-NS queries. Any device that responds should be imminently investigated.

### Stage 3: Relaying and Cracking

- Enable SMB and LDAP signing
- Ensure a strong password policy (Microsoft recommends at least 14 characters)
- Put privileged accounts into the Protected Users Security Group
