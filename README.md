# ESXiAudit
VMware ESXi Hypervisor security configuration audit.

#### Description:

The purpose of this script is to check VMware ESXi Hypervisor security configurations and provide recommendations based on best-practice for hardening and increasing visibility on an ESXi host. Once executed on the System Administrators host, the script will utilise a series of commands to query information from the target system and retrieve data, which it stores in a temporary folder. Finally, the collection is archived into a ZIP file and the temporary store is deleted. The ZIP file can then be retrieved by the analyst for subsequent analysis offline. The script should be used during posture enhancement assessments or alternatively post-breach to review security configurations of compromised hosts. A log of the terminal activities is also created and retained in the archive collection.

The following categories for each item audited are provided in a report:
- Check - What configuration was checked.
- Finding - What misconfiguration was identified posing a security risk or limiting visibility.
- Information - What sufficient configuration was identified (if no finding).
- Background - Circumstances surrounding the risk or visibility finding.

#### Usage:

Step 1: Copy script to the vSphere Administrators Windows host.

Step 2: Execute script and follow on-screen instructions.

```
.\ESXiAudit.ps1
```

If issues are encountered relating to PowerShell policies, change local policy via 'Set-ExecutionPolicy'.

Step 3: View resultant (*.zip) archive file via your preferred method.

#### Requirements:

- Ensure you have user account credentials for the target host.
- Ensure local PowerShell policies permit execution.
- PowerCLI leveraged.
