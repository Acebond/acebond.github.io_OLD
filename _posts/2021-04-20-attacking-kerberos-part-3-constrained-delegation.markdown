---
layout: post
title: 'Kerberos Abuse Part 3 - Constrained Delegation'
date: '2021-04-20 00:00:00'
img_path: /assets/img/2021-04-20/
categories: ['Red Team', 'Active Directory']
tags: []
---

I wanted to complete the The Power of Kerberos series by looking at Constrained Delegation, the last type of Kerberos delegation. This post will demonstrate how Constrained Delegation can be leveraged within an Active Directory environment for lateral movement and privilege escalation.

![CHAOS\Cyclone configured for Constrained Delegation](/assets/img/2021-04-20/image-30.png)
_CHAOS\Cyclone configured for Constrained Delegation_

## Preconditions for Constrained Delegation

1. Control of an account configured for Constrained Delegation. This could be code execution within the context of the account, the account password or NTLM hash.
2. The account configured for Constrained Delegation has the "Use any authentication protocol" option selected or you have obtained the TGS of the user to impersonate.

## Background Knowledge

An attacker can abuse intended or misconfigured accounts that have the **msds-AllowedToDelegateTo** property (referred to as "Services to which this account can present delegated credentials" in the above screenshot) to impersonate nearly any user within the domain to any host configured in the property. The exceptions would be users which have the attribute **Cannot Be Delegated** set to **True** or members of the **Protected Users** group.

If the account is configured for Constrained Delegation with the option "Use any authentication protocol" selected, the **TRUSTED\_TO\_AUTH\_FOR\_DELEGATION** property flag within the **UserAccountControl** attribute will be set. This property flag as [described by the Microsoft documentation](https://docs.microsoft.com/en-US/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) allows the account to perform the S4U2self operation, meaning the account can obtain a service ticket to itself on behalf of a user. This is the ideal setup for abusing Constrained Delegation and will be the setup used within the Performing the Attack section of this blog post.

The alternative situation would be the "Use Kerberos only" option, which requires waiting for a victim to present its service ticket so it can be used for delegation. This would entail monitoring the computer running the Constrained Delegation service for the TGS of an appropriate victim, most likely an admin to the host being targeted from the **msds-AllowedToDelegateTo** property. This ticket can be used in the Rubeus s4u action with the **/tgs** parameter.

Accounts configured for Constrained Delegation can be found using PowerView or BloodHound. The below images show that the CHAOS\Cyclone user account is configured for Constrained Delegation to INDIGON. Its important to note the **msds-AllowedToDelegateTo** and **UserAccountControl** properties as this determines which hosts can be compromised and if the S4U2self operation can be performed. The service class part of the SPN is irrelevant as alternative services can always be requested.

![Finding accounts configured for Constrained Delegation](/assets/img/2021-04-20/image-25.png)
_Finding accounts configured for Constrained Delegation_


![BloodHound showing a Constrained Delegation attack path](/assets/img/2021-04-20/image-26.png)
_BloodHound showing a Constrained Delegation attack path_

## Performing the Attack

I have chosen to perform the attack within the context of CHAOS\Cyclone. No credentials or elevated privileges are required. First dump the CHAOS\Cyclone TGT using Rubeus. Note that if the TGT does not exist, you can force Windows to request it using a command like `net user Cyclone /domain`.

![Dumping the Cyclone TGT using Rubeus](/assets/img/2021-04-20/image-27.png)
_Dumping the Cyclone TGT using Rubeus_

Perform the Rubeus s4u action using the dumped TGT (with the **/ticket** parameter). Note that the s4u action can also be performed with the NTLM hash (using **/rc4** ), or Kerberos keys (using **/aes256** ) which can be calculated from the account password.

You must specify in the / **msdsspn** parameter, a SPN from the **msds-AllowedToDelegateTo** attribute as discussed earlier. This is the target server to compromise. The **/altservice** parameter can be used to request Kerberos tickets for any service on the target. The example below requests CIFS for filesystem access.

The user being impersonated should have administrative privileges to the target machine - in the example below, the domain admin CHAOS\Alpha has been chosen.

    Rubeus s4u /impersonateuser:alpha /msdsspn:time/Indigon.CHAOS.local /altservice:cifs /ptt /ticket:doIFCjCCBQagAwIBB...(snip)...

![Rubeus s4u action being executed](/assets/img/2021-04-20/image-29.png)
_Rubeus s4u action being executed_

Admin privileges on INDIGON have been achieved as evident by listing the directory contents of the C$ share.

![Access to the C$ share on INDIGON](/assets/img/2021-04-20/image-28.png)
_Access to the C$ share on INDIGON_

## References

- [https://github.com/GhostPack/Rubeus#constrained-delegation-abuse](https://github.com/GhostPack/Rubeus#constrained-delegation-abuse)
- [http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://twitter.com/HackAndDo](https://twitter.com/HackAndDo)
