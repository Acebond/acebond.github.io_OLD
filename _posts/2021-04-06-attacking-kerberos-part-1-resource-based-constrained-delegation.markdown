---
layout: post
title: 'Kerberos Abuse Part 1 - Resource-Based Constrained Delegation'
date: '2021-04-06 00:00:00'
img_path: /assets/img/2021-04-06/
categories: ['Red Team', 'Active Directory']
tags: []
---

Imagine the below setup, with Bravo being a low privileged user, and HEADHUNTER being configured with Unconstrained Delegation.

![Bravo has GenericWrite to HEADHUNTER](/assets/img/2021-04-06/image.png)

This can be exploited to achieve Domain Admin privileges by performing a Resource-Based Constrained Delegation (RBCD) attack to gain control of HEADHUNTER. Then using Unconstrained Delegation on HEADHUNTER to gain control of the Domain Controller via the printer bug.

## Preconditions for RBCD

1. We have code execution within the context of CHAOS\Bravo
2. CHAOS\Bravo has any of GenericAll, GenericWrite, WriteDacl, WriteProperty, etc on HEADHUNTER to configure the **msDS-AllowedToActOnBehalfOfOtherIdentity** attribute
3. The domain has at least one Domain Controller running at least Windows Server 2012
4. We have control of an account with an SPN configured or the ability to create one. Note that by default all members of Domain Users can create new machines accounts which meets this requirement. This account will be referred to as ATTACKER1.

## Performing the Attack

Normally you would observe #2 in BloodHound or PowerView and begin planning the attack. Unless you have control of an account with an SPN, from say obtaining administrative privileges on a computer within the domain or Kerberoasting, you will have to create a new machine account using [Powermad](https://github.com/Kevin-Robertson/Powermad). The machine account will by default have several SPNs registered.

    New-MachineAccount -MachineAccount ATTACKER1 -Password $(ConvertTo-SecureString 'CovidSucks2021' -AsPlainText -Force) -Verbose

![Add a new machine account directly through an LDAP add request to a domain controller](/assets/img/2021-04-06/image-1.png)
_Add a new machine account directly through an LDAP add request to a domain controller_

Next configure RBCD on the target computer, delegating impersonation rights to ATTACKER1. This can be performed using an updated version of [PowerView](https://github.com/ZeroDayLab/PowerSploit/tree/master/Recon). While we can delegate access to any account, the Rubeus s4u action in the next step requires that the account setup for RBCD contain at least one SPN, which is why ATTACKER1 has been chosen.

    Set-DomainRBCD HEADHUNTER -DelegateFrom ATTACKER1 -Verbose

![Configure RBCD on HEADHUNTER to allow ATTACKER1 delegation rights](/assets/img/2021-04-06/image-2.png)
_Configure RBCD on HEADHUNTER to allow ATTACKER1 delegation rights_

To perform the Rubeus s4u action, we must provide a TGT (using **/ticket** ) or hash (using **/rc4** or **/aes256** ) of the account allowed to perform RBCD, which is ATTACKER1 in our instance. The `aes256` key is considered the best for OPSEC. We can calculate the Kerberos encryption keys for ATTACKER1 with the command:

    Rubeus.exe hash /user:ATTACKER1$ /password:CovidSucks2021 /domain:CHAOS.LOCAL

![Calculate the Kerberos encryption keys using the username/password](/assets/img/2021-04-06/image-7.png)
_Calculate the Kerberos encryption keys using the username/password_

In the instance you are using an already compromised computer account, you will need the Kerberos encryption keys, which are derived from the machine account password. These can be obtained using the Mimikatz command `sekurlsa::ekeys`, dumped remotely using [SharpSecDump](https://github.com/G0ldenGunSec/SharpSecDump), or calculated using the above Rubeus command and the machine account password.

Now use [Rubeus](https://github.com/GhostPack/Rubeus) to perform S4U2Self and S4U2Proxy to impersonate a user to the target computer. These Kerberos protocol extensions are outside the scope of this blog post but references have been included that explain the technical details. The Kerberos ticket requests require an SPN that exists on HEADHUNTER be specified (using **/msdsspn** ), and TERMSRV/HEADHUNTER.CHAOS.local, found using BloodHound, has been chosen. Note that the HOST SPN, which often and does exist in my case, is a catch all for several SPNs which are determined by the **SPNmappings** attribute. You can therefore choose say DCOM/HEADHUNTER.CHAOS.local, which does not explicitly exist on HEADHUNTER, but will be handled by HOST.

The user being impersonated should have administrative privileges to the target machine - in the example below, the domain admin CHAOS\Alpha has been chosen. Note that you cannot choose a user which has the attribute **Cannot Be Delegated** set to **True** or members of the **Protected Users** group. These conditions can be checked using BloodHound.

If Rubeus does not choose a Domain Controller running at least **Windows Server 2012** you will have to manually specify the Domain Controller with the **/dc** parameter. Alternative services can be requested with the **/altservice** parameter. I normally request HOST and RPCSS for WMI, and CIFS for SMB access.

    Rubeus.exe s4u /user:ATTACKER1$ /aes256:60BD5F4939AB0F848C5DD3B5650FB772C4718CA58223389CE361940D56508CDD /impersonateuser:ALPHA /msdsspn:TERMSRV/HEADHUNTER.CHAOS.local /domain:CHAOS.LOCAL /altservice:host,cifs,RPCSS /nowrap /ptt

![Rubeus s4u action using the aes256 hash](/assets/img/2021-04-06/image.png)
_Rubeus s4u action using the aes256 hash_

Lateral movement can now be performed using a number of techniques. We can perform [DLL hijacking](/posts/edgegdi-dll-for-persistence-and-lateral-movement) using SMB access, execute commands with WMI, setup remote scheduled tasks, etc. The below example copies an MSBuild payload onto HEADHUNTER and executes it using WMI. Note the usage of the fully qualified domain name (FQDN) is **VERY IMPORTANT**.

![Lateral movement with WMI](/assets/img/2021-04-06/image-6.png)
_Lateral movement with WMI_

[Part 2](/posts/attacking-kerberos-part-2-unconstrained-delegation/) will continue from HEADHUNTER and demonstrate obtaining Domain Admin privileges using Unconstrained Delegation and the printer bug.

## References

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://adsecurity.org/?p=2011](https://adsecurity.org/?p=2011)
