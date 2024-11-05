###################################################################################
#
#    Script:    ESXiAudit.ps1
#    Version:   1.1
#    Author:    Dan Saunders
#    Contact:   dcscoder@gmail.com
#    Purpose:   ESXi Security Configuration Audit Script (PowerShell)
#    Usage:     .\ESXiAudit.ps1
#
#    This program is free software: you can redistribute it and / or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <https://www.gnu.org/licenses/>.
#
###################################################################################

$Script = "ESXiAudit"
$Version = "v1.1"

########## Startup ##########

Write-Host "

           _______   _______ ___    ___         __                   __
          |   ____| /  _____|\  \  /  / __     /  \                 |  | __  ________
          |  |____ |   \___   \  \/  / |__|   / /\ \    __    __  __|  ||__||__    __|
          |   ____| \__    \  |      | |  |  / /__\ \  |  |  |  ||  _  ||  |   |  |
          |  |____  ____\   | /  /\  \ |  | /  ____  \ |  |__|  || |_| ||  |   |  |
          |_______||_______/ /__/  \__\|__|/__/    \__\|________||_____||__|   |__|
			

	    Script: ESXiAudit.ps1 - $Version - Author: Dan Saunders dcscoder@gmail.com`n`n"

Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Please Note:

Hi $env:USERNAME, script running on $env:ComputerName, please follow instructions.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~`n" -ForegroundColor yellow -BackgroundColor black

########## Admin ##########

# Destination
$Destination = $PSScriptRoot
# System Date/Time
$Timestamp = ((Get-Date).ToString('_yyyyMMdd_HHmmss'))

# Connectivity
$TargetHost = Read-Host -Prompt "Enter Target IP Address"
$Credentials = Get-Credential -Message "ESXiAudit $Version - Please enter your credentials."
Write-Host "`nInitiating connection to vCenter server..." -ForegroundColor green -BackgroundColor black
try
{
	Connect-VIServer -Server $TargetHost -Cred $Credentials -ea SilentlyContinue
	Get-VMHost | Select Name, ConnectionState, PowerState 
}
catch
{
	Write-Host "Connection to vCenter server failed. Check target host is reachable and credentials were entered correctly and try again!" -ForegroundColor red -BackgroundColor black
	break
}

# Triage
$Name = $Script+"_"+$TargetHost+$Timestamp
$Audit = $Name
$Report = "ESXiAudit_Security_Configuration_Report.txt"

# Stream Events
Start-Transcript $Destination\$Audit\ESXiAudit.log -Append | Out-Null

# Directory Structure
New-Item $Destination\$Audit\RawData -ItemType Directory | Out-Null

# Report
Write-Output "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Security Configuration Report - $Script $Version
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" > $Destination\$Audit\$Report

# ESXCLI
$EsxCli = Get-EsxCli -v2

Write-Host "Progressing to audit..." -ForegroundColor green -BackgroundColor black

# Dump Advanced Settings 
Get-VMHost | Get-AdvancedSetting | Format-List | Out-File $Destination\$Audit\RawData\"Advanced_Settings.txt" -ea SilentlyContinue

# execInstalledOnly
Write-Output "`r`nCheck: execInstalledOnly" >> $Destination\$Audit\$Report
$ExecSetting = "VMkernel.Boot.execInstalledOnly"
$ExecRecommended = "True"
$ExecData = (Get-VMHost | Get-AdvancedSetting -Name $ExecSetting | Select -ExpandProperty Value -ea SilentlyContinue)
	if ($ExecData -Eq $ExecRecommended) {
		Write-Output "Information: execInstalledOnly is set to 'True'. execInstalledOnly is enabled." >> $Destination\$Audit\$Report}
	elseif ($ExecData -Ne $ExecRecommended) { 
		Write-Output "Finding: execInstalledOnly is set to 'False'. execInstalledOnly is disabled. `nBackground: Threat actors may attempt to execute binaries not part of an authorised signed vSphere Installation Bundle (VIB). `nRecommendation: Set the configuration to '$ExecRecommended', to ensure execInstalledOnly is enabled." >> $Destination\$Audit\$Report}

# Lockdown Mode
Write-Output "`r`nCheck: Lockdown Mode" >> $Destination\$Audit\$Report
$LockdownSetting = ".ExtensionData.Config.LockdownMode"
$LockdownRecommended = "lockdownDisabled"
$LockdownData = (Get-VMHost).$LockdownSetting | Select -ExpandProperty Value -ea SilentlyContinue
	if ($LockdownData -Ne $LockdownRecommended) {
		Write-Output "Information: Lockdown mode is set to 'lockdownEnabled'. Lockdown mode is enabled." >> $Destination\$Audit\$Report}
	elseif ($LockdownData -Eq $LockdownRecommended) { 
		Write-Output "Finding: Lockdown mode is set to 'lockdownDisabled'. Lockdown mode is disabled. `nBackground: Threat actors may attempt to leverage services using privileged users to execute nefarious tasks. Lockdown mode forces the use of vCenter, unless user is exempt on exceptions list. `nRecommendation: Set the configuration to '$LockdownRecommended', to ensure lockdown mode is enabled." >> $Destination\$Audit\$Report}

# Suppress Shell Warning
Write-Output "`r`nCheck: Suppress Shell Warning" >> $Destination\$Audit\$Report
$SupShellSetting = "UserVars.SuppressShellWarning"
$SupShellRecommended = "0"
$SupShellData = (Get-VMHost | Get-AdvancedSetting -Name $SupShellSetting | Select -ExpandProperty Value -ea SilentlyContinue)
	if ($SupShellData -Ne $SupShellRecommended) {
		Write-Output "Finding: Suppress shell warning is set to '1'. Suppress shell warning is enabled. `nBackground: Threat actors may modify notifications as part of defence evasion tactics to avoid alerting an IT Administrator. `nRecommendation: Set the configuration to '$SupShellRecommended', to ensure suppress shell warning is disabled." >> $Destination\$Audit\$Report}
	elseif ($SupShellData -Eq $SupShellRecommended) { 
		Write-Output "Information: Suppress shell warning is set to '0'. Suppress shell warning is disabled." >> $Destination\$Audit\$Report}

# Protocols
Write-Output "`r`nCheck: Protocols" >> $Destination\$Audit\$Report
$ProtocolSetting = "UserVars.ESXiVPsDisabledProtocols"
$ProtocolRecommended = "tlsv1,tlsv1.1,sslv3"
$ProtocolVar1 = "tlsv1,tlsv1.1,sslv3"
$ProtocolVar2 = "sslv3,tlsv1,tlsv1.1"
$ProtocolVar3 = "sslv3"
$ProtocolData = (Get-VMHost | Get-AdvancedSetting -Name $ProtocolSetting | Select -ExpandProperty Value -ea SilentlyContinue)
	if ($ProtocolData -Contains $ProtocolVar1) {
		Write-Output "Information: Protocols configured are exclusively enabled for transport layer security (TLS) 1.2." >> $Destination\$Audit\$Report}
	elseif ($ProtocolData -Contains $ProtocolVar2) {
		Write-Output "Information: Protocols configured are exclusively enabled for transport layer security (TLS) 1.2." >> $Destination\$Audit\$Report}
	elseif ($ProtocolData -Contains $ProtocolVar3) {
		Write-Output "Finding: Protocols configured are not exclusively enabled for transport layer security (TLS) 1.2. `nBackground: Threat actors may exploit vulnerabilities associated with deprecated protocols. `nRecommendation: Set the configuration to '$ProtocolRecommended', to ensure deprecated protocols are disabled." >> $Destination\$Audit\$Report}
	else { 
		Write-Output "Finding: Protocols configured are not exclusively enabled for transport layer security (TLS) 1.2. `nBackground: Threat actors may exploit vulnerabilities associated with deprecated protocols. `nRecommendation: Set the configuration to '$ProtocolRecommended', to ensure deprecated protocols are disabled." >> $Destination\$Audit\$Report}

# OpenSLP
Write-Output "`r`nCheck: OpenSLP" >> $Destination\$Audit\$Report
$SLPSetting = "slpd"
$SLPRecommended = "off"
$SLPOn = "on"
$SLPData = (Get-VMHost | Get-VMHostService | Where {$_.Label -Eq $SLPSetting} | Select -ExpandProperty Policy -ea SilentlyContinue)
	if ($SLPData -Eq $SLPRecommended) {
		Write-Output "Information: OpenSLP network service policy is set to 'off'. OpenSLP policy is disabled." >> $Destination\$Audit\$Report}
	elseif ($SLPData -Eq $SLPOn) { 
		Write-Output "Finding: OpenSLP network service policy is set to 'on'. OpenSLP is policy enabled. `nBackground: Threat actors may exploit vulnerabilities associated with the OpenSLP network service via port 427. `nRecommendation: Set the configuration to '$SLPRecommended', to ensure OpenSLP policy is disabled." >> $Destination\$Audit\$Report}
	else { 
		Write-Output "Information: OpenSLP network service policy is not present. OpenSLP policy is not enabled." >> $Destination\$Audit\$Report}
		
# Persistent Log Location
Write-Output "`r`nCheck: Persistent Log Location" >> $Destination\$Audit\$Report
$PersLogDirSetting = "Syslog.global.logDir"
$PersLogScratchSetting = "ScratchConfig.CurrentScratchLocation"
$PersLogRecommended = "True"
$PersLogStatusData = $EsxCli.system.syslog.config.get.Invoke() | Select -ExpandProperty LocalLogOutputIsPersistent -ea SilentlyContinue
$PersLogDirData = (Get-VMHost | Get-AdvancedSetting -Name $PersLogDirSetting | Select -ExpandProperty Value -ea SilentlyContinue)
$PersLogScratchData = (Get-VMHost | Get-AdvancedSetting -Name $PersLogScratchSetting | Select -ExpandProperty Value -ea SilentlyContinue)
	if ($PersLogStatusData -Eq $PersLogRecommended) {
		Write-Output "Information: Persistent log location is populated. Persistent log location is configured (Path: $PersLogDirData | Scratch: $PersLogScratchData)." >> $Destination\$Audit\$Report}
	elseif ($PersLogStatusData -Ne $PersLogRecommended) { 
		Write-Output "Finding: Persistent log location is empty (RAW: $PersLogStatusData Path: $PersLogDirData). Persistent log location is not configured. `nBackground: Persistent log location must be configured to retain logs, otherwise this limits visibility and detection opportunities. `nRecommendation: Set the configuration to '$PersLogRecommended', to ensure a persistent log location is configured." >> $Destination\$Audit\$Report}

# Log Forwarding
Write-Output "`r`nCheck: Log Forwarding" >> $Destination\$Audit\$Report
$ForLogSetting = "Syslog.global.logHost"
$ForLogRecommended = "use one of the following protocols/ports udp://:514 tcp://:514 ssl://:1514"
$ForLogData = (Get-VMHost | Get-AdvancedSetting -Name $ForLogSetting | Select -ExpandProperty Value -ea SilentlyContinue)
	if ($ForLogData) {
		Write-Output "Information: Log forwarding is not NULL. Log forwarding is configured (RAW: $ForLogData)." >> $Destination\$Audit\$Report}
	else { 
		Write-Output "Finding: Log forwarding is NULL. Log forwarding is not configured. `nBackground: Log forwarding must be configured to centrally store logs, otherwise this limits visibility and detection opportunities. `nRecommendation: Set the configuration to $ForLogRecommended and forward logs to a central store for monitoring." >> $Destination\$Audit\$Report}

# vSphere Installed Bundles (VIB)
Write-Output "`r`nCheck: vSphere Installed Bundles (VIB)" >> $Destination\$Audit\$Report
$AccLvlSetting = "CommunitySupported"
$AccLvlRecommended = "not allow CommunitySupported VIB packages"
$AccLvlData = $EsxCli.software.vib.list.Invoke() | Where AcceptanceLevel -Like $AccLvlSetting | Select -ExpandProperty AcceptanceLevel -ea SilentlyContinue
	if ($AccLvlData) {
		Write-Output "Finding: CommunitySupported vSphere installed bundles is not NULL. CommunitySupported VIBs are installed (RAW: See RawData folder). `nBackground: Threat actors may attempt to install malicious VIBs for persistence and execution purposes. `nRecommendation: Set the configuration to $AccLvlRecommended, to ensure unsigned/uncertified VIBs are prevented from being used." >> $Destination\$Audit\$Report
		try
		{
			$EsxCli.software.vib.list.Invoke() | Where AcceptanceLevel -Like $AccLvlSetting | Out-File $Destination\$Audit\RawData\vSphere_Installed_Bundles.txt -ea SilentlyContinue
		}
		catch
		{

		}
		}
	else { 
		Write-Output "Information: CommunitySupported vSphere installed bundles is NULL. CommunitySupported VIBs are not installed." >> $Destination\$Audit\$Report}
				
# DCUI Timeout
Write-Output "`r`nCheck: DCUI Timeout" >> $Destination\$Audit\$Report
$DCUISetting = "UserVars.DcuiTimeOut"
$DCUIRecommended = "600"
$DCUIData = (Get-VMHost | Get-AdvancedSetting -Name $DCUISetting | Select -ExpandProperty Value -ea SilentlyContinue)
	if ($DCUIData -Gt $DCUIRecommended) {
		Write-Output "Finding: DCUI timeout' is greater than 10 minutes (RAW: $DCUIData). DCUI timeout is not sufficient. `nBackground: Threat actors may leverage the Direct User Console Interface (DCUI) to modify the ESXi host configurations. `nRecommendation: Set the configuration to '$DCUIRecommended', to ensure DCUI timeout is 10 minutes." >> $Destination\$Audit\$Report}
	elseif ($DCUIData -Le $DCUIRecommended) { 
		Write-Output "Information: DCUI timeout is less than or equal to 10 minutes (RAW: $DCUIData). DCUI timeout is sufficient." >> $Destination\$Audit\$Report}

# Shell Timeout
Write-Output "`r`nCheck: Shell Timeout" >> $Destination\$Audit\$Report
$ShellSetting = "UserVars.ESXiShellTimeOut"
$ShellRecommended = "600"
$ShellData = (Get-VMHost | Get-AdvancedSetting -Name $ShellSetting | Select -ExpandProperty Value -ea SilentlyContinue)
	if ($ShellData -Gt $ShellRecommended) {
		Write-Output "Finding: Shell timeout' is greater than 10 minutes (RAW: $ShellData). Shell timeout is not sufficient. `nBackground: Threat actors may leverage the ESXi shell and secure shell (SSH) services to execute commands and perform lateral movement on the ESXi host. `nRecommendation: Set the configuration to '$ShellRecommended', to ensure shell timeout is 10 minutes." >> $Destination\$Audit\$Report}
	elseif ($ShellData -Le $ShellRecommended) { 
		Write-Output "Information: Shell timeout is less than or equal to 10 minutes (RAW: $ShellData). Shell timeout is sufficient." >> $Destination\$Audit\$Report}

# SSH Idle Timeout
Write-Output "`r`nCheck: SSH Idle Timeout" >> $Destination\$Audit\$Report
$SSHSetting = "UserVars.ESXiShellInteractiveTimeOut"
$SSHRecommended = "300"
$SSHData = (Get-VMHost | Get-AdvancedSetting -Name $SSHSetting | Select -ExpandProperty Value -ea SilentlyContinue)
	if ($SSHData -Gt $SSHRecommended) {
		Write-Output "Finding: SSH idle timeout is greater than 5 minutes (RAW: $SSHData). SSH idle timeout is not sufficient. `nBackground: Threat actors may attempt to hijack idle SSH sessions. `nRecommendation: Set the configuration to '$SSHRecommended', to ensure SSH idle timeout is 5 minutes." >> $Destination\$Audit\$Report}
	elseif ($SSHData -Le $SSHRecommended) { 
		Write-Output "Information: SSH idle timeout is less than or equal to 5 minutes (RAW: $SSHData). SSH idle timeout is sufficient." >> $Destination\$Audit\$Report}

# Failed Logon Attempts
Write-Output "`r`nCheck: Failed Logon Attempts" >> $Destination\$Audit\$Report
$FailedLogonSetting = "Security.AccountLockFailures"
$FailedLogonRecommended = "3"
$FailedLogonData = (Get-VMHost | Get-AdvancedSetting -Name $FailedLogonSetting | Select -ExpandProperty Value -ea SilentlyContinue)
	if ($FailedLogonData -Gt $FailedLogonRecommended) {
		Write-Output "Finding: Failed logon attempts is greater than 3 (RAW: $FailedLogonData). Failed logon attempts is not sufficient. `nBackground: Threat actors may attempt a brute-force attack against a user account password. `nRecommendation: Set the configuration to '$FailedLogonRecommended', to ensure failed logon attempts is limited to 3." >> $Destination\$Audit\$Report}
	elseif ($FailedLogonData -Le $FailedLogonRecommended) { 
		Write-Output "Information: Failed logon attempts is less than or equal to 3 (RAW: $FailedLogonData). Failed logon attempts is sufficient." >> $Destination\$Audit\$Report}

# Failed Logon Unlock Timeout
Write-Output "`r`nCheck: Failed Logon Unlock Timeout" >> $Destination\$Audit\$Report
$FailedUnlockSetting = "Security.AccountUnlockTime"
$FailedUnlockRecommended = "900"
$FailedUnlockData = (Get-VMHost | Get-AdvancedSetting -Name $FailedUnlockSetting | Select -ExpandProperty Value -ea SilentlyContinue)
	if ($FailedUnlockData -Lt $FailedUnlockRecommended) {
		Write-Output "Finding: Failed logon unlock timeout is less than 15 minutes (RAW: $FailedUnlockData). Failed logon unlock timeout is not sufficient. `nBackground: Threat actors may attempt a brute-force attack against a user account password. `nRecommendation: Set the configuration to '$FailedUnlockRecommended', to ensure failed logon unlock timeout is 15 minutes." >> $Destination\$Audit\$Report}
	elseif ($FailedUnlockData -Gt $FailedUnlockRecommended) {
		Write-Output "Finding: Failed logon unlock timeout is greater than 15 minutes (RAW: $FailedUnlockData). Failed logon unlock timeout is not sufficient. `nBackground: Threat actors may attempt a brute-force attack against a user account password. `nRecommendation: Set the configuration to '$FailedUnlockRecommended', to ensure failed logon unlock timeout is 15 minutes." >> $Destination\$Audit\$Report}
	elseif ($FailedUnlockData -Eq $FailedUnlockRecommended) { 
		Write-Output "Information: Failed logon unlock timeout is equal to 15 minutes (RAW: $FailedUnlockData). Failed logon unlock timeout is sufficient." >> $Destination\$Audit\$Report}
	
########## Organise Collection ##########

Stop-Transcript | Out-Null

# Compress Archive
Get-ChildItem -Path $Destination\$Audit | Compress-Archive -DestinationPath $Destination\$Audit.zip -CompressionLevel Fastest

# Delete Folder
Get-ChildItem -Path "$Destination\$Audit\\*" -Recurse | Remove-Item -Force -Recurse
Remove-Item "$Destination\$Audit"

Write-Host "`nScript completed!" -ForegroundColor green -BackgroundColor black
