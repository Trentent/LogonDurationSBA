#Requires -version 3
#Requires -RunAsAdministrator

<#
 	.SYNOPSIS
        An advanced function that gives you a break-down analysis of a user's most recent logon on the machine.
		
    .DESCRIPTION
        This function gives a detailed report on the logon process and its phases.
        Each phase documented have a column for duration in seconds, start time, end time
        and interim delay which is the time that passed between the end of one phase
        and the start of the one that comes after.
		
	.PARAMETER  <UserName <string[]>
		The user name the function reports for. The default is the user who runs the script.
		
	.PARAMETER	<UserDomain <string[]>
		The user domain name the function reports for. The default is the domain name of the user who runs the script.

	.PARAMETER  <HDXSessionId>560
		The Session ID of the user the function reports for. 
        Required for the "HDX Connection" phase,
        The machine the script runs on has to be part of the Citrix Site.

	.PARAMETER  <XDUsername>
        A User with administrative permissions to the Citrix XenApp/XenDesktop Site, at least Read-Only
        privileges, the machine the script runs on has to be part of the Citrix Site.
	
    .PARAMETER  <XDPassword>
		Password for the Citrix Site user provided.

	.PARAMETER  <CUDesktopLoadTime>
		Specifies the duration of the Shell phase, can be used with ControlUp as passed argument.

	.PARAMETER  <ClientName>
		Specifies the client name of the Citrix session.
    
    .NOTES
        The HDX duration is a new metric that requires changes to the ICA protocol. 
        This means that, if the new version of the client is not being used, the metrics returned are NULL.
        It may take a few seconds until the HDX duration is reported and available at the Delivery Controller.
		
    .LINK
        For more information refer to:
            http://www.controlup.com

    .LINK
        Stay in touch:
        http://twitter.com/nironkoren

    .EXAMPLE
        C:\PS> Get-LogonDurationAnalysis -UserName Rick
		
		Gets analysis of the logon process for the user 'Rick' in the current domain.
#>

## Last modified 1735 GMT 07/05/19 @guyrleech

## A mechanism to allow script use offline with saved event logs
[hashtable]$global:terminalServicesParams = @{ 'ProviderName' = 'Microsoft-Windows-TerminalServices-LocalSessionManager' }
[hashtable]$global:securityParams = @{ 'ProviderName' = 'Microsoft-Windows-Security-Auditing' }
[hashtable]$global:userProfileParams = @{ 'ProviderName' = 'Microsoft-Windows-User Profile Service' }
[hashtable]$global:groupPolicyParams = @{ 'ProviderName' = 'Microsoft-Windows-GroupPolicy' }
[hashtable]$global:scheduledTasksParams = @{ 'ProviderName' = 'Microsoft-Windows-TaskScheduler' }
[hashtable]$global:citrixUPMParams = @{ 'ProviderName' = 'Citrix Profile Management' }
[hashtable]$global:printServiceParams = @{ 'ProviderName' = 'Microsoft-Windows-PrintService' }
[int]$global:windowsMajorVersion = [System.Environment]::OSVersion.Version.Major
[bool]$offline = $false
[int]$suggestedSecurityEventLogSizeMB = 100
[int]$outputWidth = 400
$DebugPreference = 'SilentlyContinue'
         
    <#
    using System;
    using System.Text;
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Principal;
    using LSA_HANDLE = IntPtr;
    #>
 
$AuditDefinitions = @'
    /// The AuditFree function frees the memory allocated by audit functions for the specified buffer.
    /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375654(v=vs.85).aspx
    [DllImport("advapi32.dll")]
    public static extern void AuditFree(IntPtr buffer);

    /// The AuditQuerySystemPolicy function retrieves system audit policy for one or more audit-policy subcategories.
    /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375702(v=vs.85).aspx
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AuditQuerySystemPolicy(Guid pSubCategoryGuids, uint PolicyCount, out IntPtr ppAuditPolicy);
        
    /// The AuditQuerySystemPolicy function retrieves system audit policy for one or more audit-policy subcategories.
    /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375702(v=vs.85).aspx</returns>
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AuditSetSystemPolicy( IntPtr ppAuditPolicy , uint PolicyCount);

    /// The AUDIT_POLICY_INFORMATION structure specifies a security event type and when to audit that type.
    /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa965467(v=vs.85).aspx
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct AUDIT_POLICY_INFORMATION
    {
        /// A GUID structure that specifies an audit subcategory.
        public Guid AuditSubCategoryGuid;
        /// A set of bit flags that specify the conditions under which the security event type specified by the AuditSubCategoryGuid and AuditCategoryGuid members are audited.
        public AUDIT_POLICY_INFORMATION_TYPE AuditingInformation;
        /// A GUID structure that specifies an audit-policy category.
        public Guid AuditCategoryGuid;
    }

    [Flags]
    public enum AUDIT_POLICY_INFORMATION_TYPE
    {
        None = 0,
        Success = 1,
        Failure = 2,
    }

    // from https://gallery.technet.microsoft.com/scriptcenter/Grant-Revoke-Query-user-26e259b0
    public enum Rights
    {
        SeTrustedCredManAccessPrivilege,             // Access Credential Manager as a trusted caller
        SeNetworkLogonRight,                         // Access this computer from the network
        SeTcbPrivilege,                              // Act as part of the operating system
        SeMachineAccountPrivilege,                   // Add workstations to domain
        SeIncreaseQuotaPrivilege,                    // Adjust memory quotas for a process
        SeInteractiveLogonRight,                     // Allow log on locally
        SeRemoteInteractiveLogonRight,               // Allow log on through Remote Desktop Services
        SeBackupPrivilege,                           // Back up files and directories
        SeChangeNotifyPrivilege,                     // Bypass traverse checking
        SeSystemtimePrivilege,                       // Change the system time
        SeTimeZonePrivilege,                         // Change the time zone
        SeCreatePagefilePrivilege,                   // Create a pagefile
        SeCreateTokenPrivilege,                      // Create a token object
        SeCreateGlobalPrivilege,                     // Create global objects
        SeCreatePermanentPrivilege,                  // Create permanent shared objects
        SeCreateSymbolicLinkPrivilege,               // Create symbolic links
        SeDebugPrivilege,                            // Debug programs
        SeDenyNetworkLogonRight,                     // Deny access this computer from the network
        SeDenyBatchLogonRight,                       // Deny log on as a batch job
        SeDenyServiceLogonRight,                     // Deny log on as a service
        SeDenyInteractiveLogonRight,                 // Deny log on locally
        SeDenyRemoteInteractiveLogonRight,           // Deny log on through Remote Desktop Services
        SeEnableDelegationPrivilege,                 // Enable computer and user accounts to be trusted for delegation
        SeRemoteShutdownPrivilege,                   // Force shutdown from a remote system
        SeAuditPrivilege,                            // Generate security audits
        SeImpersonatePrivilege,                      // Impersonate a client after authentication
        SeIncreaseWorkingSetPrivilege,               // Increase a process working set
        SeIncreaseBasePriorityPrivilege,             // Increase scheduling priority
        SeLoadDriverPrivilege,                       // Load and unload device drivers
        SeLockMemoryPrivilege,                       // Lock pages in memory
        SeBatchLogonRight,                           // Log on as a batch job
        SeServiceLogonRight,                         // Log on as a service
        SeSecurityPrivilege,                         // Manage auditing and security log
        SeRelabelPrivilege,                          // Modify an object label
        SeSystemEnvironmentPrivilege,                // Modify firmware environment values
        SeDelegateSessionUserImpersonatePrivilege,   // Obtain an impersonation token for another user in the same session
        SeManageVolumePrivilege,                     // Perform volume maintenance tasks
        SeProfileSingleProcessPrivilege,             // Profile single process
        SeSystemProfilePrivilege,                    // Profile system performance
        SeUnsolicitedInputPrivilege,                 // "Read unsolicited input from a terminal device"
        SeUndockPrivilege,                           // Remove computer from docking station
        SeAssignPrimaryTokenPrivilege,               // Replace a process level token
        SeRestorePrivilege,                          // Restore files and directories
        SeShutdownPrivilege,                         // Shut down the system
        SeSyncAgentPrivilege,                        // Synchronize directory service data
        SeTakeOwnershipPrivilege                     // Take ownership of files or other objects
    }
    public sealed class TokenManipulator
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        internal sealed class Win32Token
        {
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(
                IntPtr htok,
                bool disall,
                ref TokPriv1Luid newst,
                int len,
                IntPtr prev,
                IntPtr relen
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern IntPtr GetCurrentProcess();

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(
                IntPtr h,
                int acc,
                ref IntPtr phtok
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(
                string host,
                string name,
                ref long pluid
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern bool CloseHandle(
                IntPtr phtok
            );
        }

        public static int AddPrivilege(Rights privilege)
        {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            return Marshal.GetLastWin32Error();
        }

        public static int RemovePrivilege(Rights privilege)
        {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_DISABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            return Marshal.GetLastWin32Error();
        }
    }
'@

Function Get-SystemPolicy( [Guid]$subCategoryGuid)
{
    $buffer = [IntPtr]::Zero
    if ([Win32.Advapi32]::AuditQuerySystemPolicy( $subCategoryGuid , 1 , [ref]$buffer) -and $buffer -ne [IntPtr]::Zero )
    {
        [System.Runtime.InteropServices.Marshal]::PtrToStructure( [System.IntPtr]$buffer , [type][Win32.Advapi32+AUDIT_POLICY_INFORMATION] ) ## return
        [Win32.Advapi32]::AuditFree($buffer)
        $buffer = [IntPtr]::Zero
    }
}
        
Function Set-SystemPolicy( [Guid]$subCategoryGuid , [Guid]$categoryGuid  )
{
    [bool]$result = $false
    $policy = New-Object -TypeName 'Win32.Advapi32+AUDIT_POLICY_INFORMATION'
    [IntPtr]$buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal( [System.Runtime.InteropServices.Marshal]::SizeOf( [type]$policy.GetType() ) )
    if( $buffer -ne [IntPtr]::Zero )
    {
        $policy.AuditSubCategoryGuid = $subCategoryGuid
        $policy.AuditCategoryGuid = $categoryGuid
        $policy.AuditingInformation = [Win32.Advapi32+AUDIT_POLICY_INFORMATION_TYPE]::Success
        [System.Runtime.InteropServices.Marshal]::StructureToPtr( $policy , $buffer , $false )
        [uint64]$number = 1
        $result = [Win32.Advapi32]::AuditSetSystemPolicy( $buffer , $number ); $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if( ! $result )
        {
            Write-Warning "AuditSetSystemPolicy failed - $LastError"
        }
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal( $buffer )
        $buffer = [IntPtr]::Zero
    }
    else
    {
        Write-Warning "Failed to allocate memory for audit buffer"
    }
    $result ## return
}

Function Test-AuditSetting( [string]$GUID , [string]$name , [ref]$setting )
{
    $auditEvent = Get-SystemPolicy -subCategoryGuid $GUID
    if( $auditEvent )
    {
        $setting.Value = $auditEvent.AuditingInformation.ToString()
        ( $auditEvent.AuditingInformation -band [Win32.Advapi32+AUDIT_POLICY_INFORMATION_TYPE]::Success ) -eq [Win32.Advapi32+AUDIT_POLICY_INFORMATION_TYPE]::Success 
    }
    else
    {
        Write-Warning "Could not get setting for `"$name`" with GUID $GUID"
    }
}

Function Test-AuditSettings
{
    [CmdletBinding()]
              
    [hashtable]$requiredAuditEvents = @{
        'Process Creation'    = '0cce922b-69ae-11d9-bed3-505054503030'
        'Process Termination' = '0cce922c-69ae-11d9-bed3-505054503030'
        'Logon'               = '0cce9215-69ae-11d9-bed3-505054503030'
    }

    [string]$resultString = $null
            
    if( ! ( ([System.Management.Automation.PSTypeName]'Win32.Advapi32').Type ) )
    {
        [void](Add-Type -MemberDefinition $AuditDefinitions -Name 'Advapi32' -Namespace 'Win32' -UsingNamespace System.Text -Debug:$false)
    }
    [string]$newline = $null
    [string]$setting = $null
    ForEach( $requiredAuditEvent in ($requiredAuditEvents.GetEnumerator() ))
    {
        $result = Test-AuditSetting -GUID $requiredAuditEvent.Value -name $requiredAuditEvent.Name -setting ([ref]$setting)
        if( $result -eq $null -or $result -eq $false )
        {
            $resultString += "$($newline)Auditing of `"$($requiredAuditEvent.Name)`" is not set to at least `"Success`" as required, it is set to `"$setting`""
            $newline = "`n"
        }
    }
    $resultString
}

function Get-LogonDurationAnalysis {
    [CmdletBinding(DefaultParameterSetName="None")]
    param (
        [Parameter(Position=0,
                   Mandatory=$false)]
        [Alias('User')]
        [String]
        $Username = $env:USERNAME,
        
        [Parameter(Position=1,
                   Mandatory=$false)]
        [Alias('Domain')]
        [String]
        $UserDomain = $env:USERDOMAIN,
        
        [Parameter(Mandatory=$false)]
        [Alias('HDX')]
        [int]
        $HDXSessionId,
        
        [Parameter(Mandatory=$false)]
        [String]
        $XDUsername,
        
        [Parameter(Mandatory=$false)]
        [System.Security.SecureString]
        $XDPassword,
        
        [Parameter(Mandatory=$false)]
        [decimal]
        $CUDesktopLoadTime,

        [Parameter(Mandatory=$false)]
        [String]
        $ClientName

    )
    begin {
        $Script:Output = @()
        $Script:LogonStartDate = $null

        ## array indexes for event log property fields to make retrieval more meaningful
        ## Event id 4688 (process start)
  
        Set-Variable -Name SubjectUserName   -Value 1  -Option ReadOnly
        Set-Variable -Name SubjectDomainName -Value 2  -Option ReadOnly
        Set-Variable -Name SubjectLogonId    -Value 3  -Option ReadOnly
        Set-Variable -Name ProcessIdNew      -Value 4  -Option ReadOnly
        Set-Variable -Name NewProcessName    -Value 5  -Option ReadOnly
        Set-Variable -Name ProcessIdStart    -Value 7  -Option ReadOnly
        Set-Variable -Name TargetUserName    -Value 10 -Option ReadOnly
        Set-Variable -Name TargetDomainName  -Value 11 -Option ReadOnly
        Set-Variable -Name TargetLogonId     -Value 12 -Option ReadOnly
        Set-Variable -Name ParentProcessName -Value 13 -Option ReadOnly
        
        [string]$auditingWarning = Test-AuditSettings
        [bool]$SearchCommandLine = $false
        if ([version](Get-CimInstance Win32_OperatingSystem).version -gt ([version]6.1)) { # are we using a version of Windows newer than Windows 2008R2/Windows 7 as not implemented prior to that?
            if (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue) {
                $commandLinePolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue
                if ($commandLinePolicy -and $commandLinePolicy.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
                    if (-not($auditingWarning -like "*Process Termination*")) { #need process termination auditing enabled or else we can't find when the process finishes
                        Set-Variable -Name CommandLine -Value 8 -Option ReadOnly
                        $SearchCommandLine = $true
                    }
                }
            }
        }
        Write-Debug "Process command line auditing enabled is $SearchCommandLine"
        
        ## Event id 4689 (process stop)
        Set-Variable -Name ProcessIdStop  -Value 5 -Option ReadOnly
        Set-Variable -Name ProcessName    -Value 6 -Option ReadOnly

        # Generate a new XPath string
        function New-XPath {
            [CmdletBinding(DefaultParameterSetName="None")]  
            param(
                [ValidateNotNullOrEmpty()]
                [array]
                $EventId,
        
                [Parameter(ParameterSetName='DateTime',Mandatory=$true)]
                [DateTime]
                $FromDate,
        
                [Parameter(ParameterSetName='DateTime')]
                [DateTime]
                $ToDate,
        
                [hashtable]
                $SecurityData,
                [Alias('Data')]
        
                $EventData,
        
                [hashtable]
                $UserData ,

                [switch]
                $encode
            )
            [string]$lessThan = if( $encode ) { '&lt;' } else { '<' }
            [string]$greaterThan = if( $encode ) { '&gt;' } else { '>' }
            [System.Text.StringBuilder]$sb = "*[System[("
            $ecounter = 0
            foreach ($eid in $EventId) {
                if ($ecounter -gt 0) {
                    [void]$sb.Append(" or EventID='$eid'")
                }
                else {
                    [void]$sb.Append("EventID='$eid'")
                }
                $ecounter++
            }
            if ($ToDate) {
                [void]$sb.Append(") and TimeCreated[@SystemTime$($greaterThan)='$($FromDate.ToUniversalTime().ToString("s")).$($FromDate.ToUniversalTime().ToString("fff"))'")
                [void]$sb.Append(" and @SystemTime$($lessThan)='$($ToDate.ToUniversalTime().ToString("s")).$($FromDate.ToUniversalTime().ToString("fff"))']")
                if (!$SecurityData) {
                    [void]$sb.Append("]]")
                }
            }
            elseif ($FromDate) {
                [void]$sb.Append(") and TimeCreated[@SystemTime$($greaterThan)='$($FromDate.ToUniversalTime().ToString("s")).$($FromDate.ToUniversalTime().ToString("fff"))']")
                if (!$SecurityData) {
                    [void]$sb.Append("]]")
                }
            }
            else {
                [void]$sb.Append(")]]")
            }
            if ($SecurityData) {
                    [void]$sb.Append(" and Security[@$($SecurityData.Keys[0])='$($SecurityData.Values[0])']]]")
            }
            if ($EventData -and $EventData.GetType() -eq [hashtable]) {
                foreach ($i in $EventData.Keys) {
                    $counter = 0
                    [void]$sb.Append(" and *[EventData[Data[@Name='$i']")
                    foreach ($x in $($EventData.$i)) {
                        if ($counter -gt 0) {
                            [void]$sb.Append(" or Data=`"$($x)`"")
                        }
                        else {
                            [void]$sb.Append(" and (Data=`"$($x)`"")
                        }
                        $counter++
                    }
                    [void]$sb.Append(")]]")
                }
            }
            elseif ($EventData) {
                [void]$sb.Append(" and *[EventData[Data and (Data='$EventData')]]")
            }
            if ($UserData) {
                [void]$sb.Append(" and *[UserData[EventXML[($($UserData.Keys[0])=`'$($UserData.Values[0])`')]]]")
            }
            $sb.ToString()
        }
        
        # Get an event from the Windows Eventlog using specified parameters
        function Get-PhaseEventFromCache {
            [CmdletBinding(DefaultParameterSetName="None")]
            param (
                [ValidateNotNullOrEmpty()]
                $startEvent ,

                $endEvent ,

                [String]
                $PhaseName ,

                [decimal]
                $CUAddition 
            )
            
            if( ! $startEvent )
            {
                Write-Warning "Get-PhaseEventFromCache - no start event"
            }
            if( ! $endEvent )
            {
                if($CUAddition -gt 0 -and $startEvent ) {
                    [DateTime]$EndEvent = $StartEvent.TimeCreated.AddMilliseconds($CUAddition*1000)
                }
                else {
                    Write-Warning "Get-PhaseEventFromCache - no end event"
                }
            }
            $EventInfo = @{}
            if ($EndEvent) {
                if ((($EndEvent).GetType()).Name -eq 'DateTime') {
                    $Duration = New-TimeSpan -Start $StartEvent.TimeCreated -End $EndEvent
                    $EventInfo.EndTime = $EndEvent
                }
                else {
                    $Duration = New-TimeSpan -Start $StartEvent.TimeCreated -End $EndEvent.TimeCreated
                    $EventInfo.EndTime = $EndEvent.TimeCreated 
                }
            }
            $EventInfo.PhaseName = $PhaseName
            $EventInfo.StartTime = $StartEvent.TimeCreated
            $EventInfo.Duration = $Duration.TotalSeconds
            $PSObject = New-Object -TypeName PSObject -Property $EventInfo
            if ($EventInfo.Duration -and $PhaseName -eq 'GP Scripts' -and ($StartEvent.Properties[3]).Value) {
                $PSObject
            }
            elseif ($EventInfo.Duration -and $PhaseName -eq 'GP Scripts') {
                $sharedVars.Add( 'GPASync' , [math]::Round( $PSObject.Duration , 1 ) )
            }
            elseif ($EventInfo.Duration) {
                $PSObject
            }
        }
        
        function Get-EventLogEnabledStatus {
            [CmdletBinding(DefaultParameterSetName="None")]
            param (
                [string]$eventLog
            )

            [string]$status = $null
            if( ! [string]::IsNullOrEmpty( $eventLog ) )
            {
                $eventlogProperties = wevtutil.exe get-log $eventLog
                if( ! $? -or ! $eventlogProperties )
                {
                    $status = "Unable to find event log `"$eventLog`""
                }
                elseif( $eventlogProperties | Where-Object { $_ -match '^enabled: (.*$)' -and $Matches.Count -ge 2 -and $Matches[1] } )
                {
                    if( $Matches[1] -ne 'true' )
                    {
                        $status = "Event log `"$eventLog`" is not enabled so it cannot accept events"
                    }
                }
                else
                {
                    $status = "Unable to determine if event log `"$eventLog`" is enabled"
                }                        
            }
            $status
        }
            
        # Get an event from the Windows Eventlog using specified parameters
        function Get-PhaseEvent {
            [CmdletBinding(DefaultParameterSetName="None")]
            param (
                [AllowNull()]
                [String]
                $StartEventFile ,
                
                [AllowNull()]
                [String]
                $EndEventFile ,

                [ValidateNotNullOrEmpty()]
                [String]
                $PhaseName,
            
                [ValidateNotNullOrEmpty()]
                [String]
                $StartProvider,
            
                [ValidateNotNullOrEmpty()]
                [String]
                $EndProvider,
            
                [ValidateNotNullOrEmpty()]
                [String]
                $StartXPath,
            
                [ValidateNotNullOrEmpty()]
                [String]
                $EndXPath,
            
                [string]
                $eventLog ,

                [System.Diagnostics.Eventing.Reader.EventLogRecord]
                $StartEvent,
            
                [System.Diagnostics.Eventing.Reader.EventLogRecord]
                $EndEvent,
            
                [int]
                $CUAddition ,

                [hashtable]$sharedVars
            )
            [datetime]$started = Get-Date

            [hashtable]$startParams = if( $PSBoundParameters[ 'StartEventFile' ] ) { @{ 'Path' = $StartEventFile } } else { @{ 'ProviderName' = $StartProvider } }
            [hashtable]$endParams = if( $PSBoundParameters[ 'EndEventFile' ] ) { @{ 'Path' = $EndEventFile } } else { @{ 'ProviderName' = $EndProvider } }

            try {
                $PSCmdlet.WriteVerbose("Looking $PhaseName Events")
                if(!$StartEvent) {
                    $StartEvent = Get-WinEvent -MaxEvents 1 @startParams -FilterXPath $StartXPath -ErrorAction Stop -Verbose:$False
                }
                if (!$EndEvent) {
                    if ($StartProvider -eq 'Microsoft-Windows-Security-Auditing' -and $EndProvider -eq 'Microsoft-Windows-Security-Auditing') {
                        $EndEvent = Get-WinEvent -MaxEvents 1 @endParams -FilterXPath ("{0}{1}" -f $EndXPath,(
                            "and *[EventData[Data[@Name='ProcessId']" +
                            "and (Data=`'$($StartEvent.Properties[4].Value)`')]]")
                            ) -ErrorAction Stop # Responsible to match the process termination event to the exact process
                    }
                    elseif ($CUAddition) {
                        [DateTime]$EndEvent = $StartEvent.TimeCreated.AddSeconds($CUAddition)
                    }
                    else {
                        $EndEvent = Get-WinEvent -MaxEvents 1 @endParams -FilterXPath $EndXPath 
                    }
                }
            }
            catch {
                [string]$eventLogStatus = Get-EventLogEnabledStatus -eventLog $eventLog
                if( ! [string]::IsNullOrEmpty( $eventLogStatus ) )
                {
                    $PSCmdlet.WriteWarning( $eventLogStatus )
                }
                if ($PhaseName -ne 'Citrix Profile Mgmt' -and $PhaseName -ne 'GP Scripts') {
                    if ($StartProvider -eq 'Microsoft-Windows-Security-Auditing' -or $EndProvider -eq 'Microsoft-Windows-Security-Auditing' ) {
                        $PSCmdlet.WriteWarning("Could not find $PhaseName events (requires audit process tracking)")
                    }
                    else {
                        $PSCmdlet.WriteWarning("Could not find $PhaseName events")
                    }
                }
            }
            finally {
                $EventInfo = @{}
                if ($EndEvent) {
                    if ((($EndEvent).GetType()).Name -eq 'DateTime') {
                        $Duration = New-TimeSpan -Start $StartEvent.TimeCreated -End $EndEvent
                        $EventInfo.EndTime = $EndEvent
                    }
                    else {
                        $Duration = New-TimeSpan -Start $StartEvent.TimeCreated -End $EndEvent.TimeCreated
                        $EventInfo.EndTime = $EndEvent.TimeCreated 
                    }
                }
                $EventInfo.PhaseName = $PhaseName
                $EventInfo.StartTime = $StartEvent.TimeCreated
                $EventInfo.Duration = $Duration.TotalSeconds
                $PSObject = New-Object -TypeName PSObject -Property $EventInfo
                if ($EventInfo.Duration -and $PhaseName -eq 'GP Scripts' -and ($StartEvent.Properties[3]).Value) {
                    $PSObject
                }
                elseif ($EventInfo.Duration -and $PhaseName -eq 'GP Scripts') {
                    $sharedVars.Add( 'GPASync' , [math]::Round( $PSObject.Duration , 1 ) )
                    ##$Script:GPAsync = "{0:N1}" -f $PSObject.Duration
                }
                elseif ($EventInfo.Duration) {
                    $PSObject
                }
            }
        }

        # Connects to the Citrix Broker Monitor Service to get information about a session
        function Get-ODataPhase {
            [CmdletBinding()]
            param (
                [string]
                $SessionKeyPath = 'HKLM:\SOFTWARE\Citrix\Ica\Session\CtxSessions',
                
                [string]
                $DDCPath = 'HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent\State'
            )

            try {
                if ($PSBoundParameters[ 'Verbose' ]) {
                    $PSCmdlet.WriteVerbose("Querying registry for `"SessionKey`" in {0}" -f $SessionKeyPath)
                }
                $CtxSessionsKey = Get-ItemProperty $SessionKeyPath
                if ($PSBoundParameters[ 'Verbose' ]) {
                    $PSCmdlet.WriteVerbose("Querying registry for `"DDC`" in {0}" -f $DDCPath)
                }
                $DDC = Get-ItemProperty $DDCPath | Select-Object -ExpandProperty 'RegisteredDdcFqdn'
	            }
	        catch {
		        $PSCmdlet.WriteWarning("Could not access registry: {0}" -f ($Error[0].Exception))
	        }
	        finally {
		        $SessionsIdList = ($CtxSessionsKey | Get-Member -MemberType NoteProperty).Name | Where-Object {$_ -notmatch "PS*"}
	        }
	        if ((($SessionsIdList.GetType()).BaseType).Name -eq "Array") {
		        foreach ($i in $SessionsIdList) {
			        if ($CtxSessionsKey.$i -eq $HDXSessionId) {
				        $SessionKey = $i.Replace('({|})','')
			        }
		        }
	        }
	        else {
		        $SessionKey = $SessionsIdList.Replace('({|})','')
	        }

            try {
                Write-Debug "Checking session $sessionKey on DDC $DDC as user $XDUsername"
                $XDCreds = New-Object System.Management.Automation.PSCredential ($XDUsername, $XDPassword)
	            $ODataData = (Invoke-RestMethod -Uri "http://$DDC/Citrix/Monitor/OData/v1/Data/Sessions(guid'$SessionKey')/CurrentConnection" `
                   -Credential $XDCreds ).entry.content.properties
	            try {
		            [DateTime]$HDXStartTime = $ODataData.HdxStartDate.'#text'
		            [DateTime]$HDXEndTime = $ODataData.HdxEndDate.'#text'
	            }
	            catch {
		            $PSCmdlet.WriteWarning("No HDX duration records found.")
	            }
                finally {
                    if (($HDXStartTime) -and ($HDXEndTime)) {
		                $HDXSessionDuration = (New-TimeSpan -Start $HDXStartTime -End $HDXEndTime).TotalSeconds
                        [pscustomobject]@{
                            PhaseName = 'HDX Connection'
                            StartTime = $HDXStartTime.ToLocalTime()
                            EndTime = $HDXEndTime.ToLocalTime()
                            Duration = $HDXSessionDuration
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Could not initiate a connection to $DDC with SessionKey: $CtxSessionsKey,`n $($Error[0].Exception.Message)`n Make sure the user has at least the `"Read-Only Administrator`" role"

	            $PSCmdlet.WriteWarning((("Could not initiate a connection to {0},`n {1}`n" +
                    "Make sure the user has at least the `"Read-Only Administrator`" role") -f $DDC, $Error[0].Exception.Message))
	        }
        }

        function Get-UserLogonDetails {
            [CmdletBinding()]

            Param(
                [Parameter(Mandatory=$true)]
                [string]
                $UserName
            )
                [string[]]$sess = (quser.exe "$username" | Select -Skip 1 | Select -Last 1) -split '\s+'
                [string]$info = $null

                if( $sess -and $sess.Count )
                {
                    if( $sess[-1] -match '^[AP]M$' )
                    {
                        $info = " - logon was $($sess[-3..-1] -join ' ')"
                    }
                    else
                    {
                        $info = " - logon was $($sess[-2..-1] -join ' ')"
                    }
                }
                else
                {
                    $info = " - user $username not currently logged on"
                }
                $info
        }

        function Get-LogonTask {
            [CmdletBinding()]
            param(
            [Parameter(Mandatory=$true)]
            [string]
            $UserName,
            
            [Parameter(Mandatory=$true)]
            [string]
            $UserDomain,
            
            [Parameter(Mandatory=$true)]
            [DateTime]
            $Start,
            
            [Parameter(Mandatory=$true)]
            [DateTime]
            $End
            )

            [hashtable]$logonTaskParams = $global:scheduledTasksParams.Clone()
            $logonTaskParams.Add( 'StartTime' , $start )
            $logonTaskParams.Add( 'Id' , @(119,201) )
            [array]$logontaskEvents = @( Get-WinEvent -FilterHashtable $logonTaskParams -ErrorAction SilentlyContinue)

            $logontaskEvents | Where-Object { $_.Id -eq 119 -and $_.TimeCreated -le $end -and $_.Properties[1].Value -eq "$UserDomain\$UserName" } | ForEach-Object `
            {
                $taskStart = $_
                $taskEnd = $logontaskEvents | Where-Object { $_.Id -eq 201 -and $taskStart.Properties[2].Value -eq $_.Properties[1].Value }  ## Correlate task instance id
                if( $taskEnd )
                {
                    New-Object -TypeName psobject -Property @{ 
                            'TaskName'="$($TaskEnd.Properties[0].Value)"
                            'ActionName'="$($TaskEnd.Properties[2].Value)"
                            'Duration'=$taskEnd.TimeCreated - $taskStart.TimeCreated
                        }
                } 
            }
        }

 function Get-PrinterEvents {
            [CmdletBinding()]
            param(
            [Parameter(Mandatory=$true)]
            [DateTime]
            $Start,
            
            [Parameter(Mandatory=$true)]
            [DateTime]
            $End,

            [Parameter(Mandatory=$false)]
            [String]
            $ClientName
            )

            Write-Verbose "Get-PrinterEvents Start Time: $start"
            Write-Verbose "Get-PrinterEvents End Time: $end"
            Write-Verbose "Get-PrinterEvents ClientName: $ClientName"

            if( ! $offline )
            {
                [string]$eventLogStatus = Get-EventLogEnabledStatus -eventLog 'Microsoft-Windows-PrintService/Operational'
                if( ! [string]::IsNullOrEmpty( $eventLogStatus ) )
                {
                    $PSCmdlet.WriteWarning( $eventLogStatus )
                    return
                }
            }

            if( [string]::IsNullOrEmpty( $End ) )
            {
                $PSCmdlet.WriteWarning( "No logon end event was found.  Please wait and try again once logon has completed.  Printer information will not be displayed." )
                return
            }

            if (-not(Test-Path HKU:\)) {
                New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | out-null
            }

            if (-not(Test-Path HKU:\$($Logon.UserSID)\Printers\Connections\ -ErrorAction SilentlyContinue)) {
                Write-Verbose "Unable to find mapped printers in the user session."  #we'll do our best though with what's available
            } else {
                $UserPrinterGUIDs += Get-ItemProperty -Path HKU:\$($Logon.UserSID)\Printers\Connections\* -Name GuidPrinter
                $PrintServers = (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider\Servers").PSChildName
                Write-Verbose "Found the following print servers:"
                Write-Verbose "$printServers"
                foreach ($printServer in $printServers) {
                  $PrinterClientSidePortGUIDs += Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider\Servers\$printServer\Monitors\Client Side Port\*" -Name PrinterPath
                }
                if ($DebugPreference -eq "continue") {
                    Write-Debug "Printer GUIDS:"
                    foreach ($ClientSidePortGUID in $PrinterClientSidePortGUIDs) {
                        Write-Debug "$($ClientSidePortGUID.printerPath)"
                    }
                }
    
            }
            [hashtable]$printerParams = $global:printServiceParams.Clone() +  @{ StartTime = $start ; EndTime = $end ; Id = 300,306}
            [array]$printerTaskEvents = @( Get-WinEvent -FilterHashtable $printerParams -ErrorAction SilentlyContinue )
            if ($printerTaskEvents.count -eq 0) {
                #no printer events found.  This may occur if the application is not set to wait for printers (totally normal!) so just return without a message
                Write-Verbose "No Printer Events Found."
                return
            }
            #get list of printers:
            $listOfPrinters = [System.Collections.ArrayList]@()
            $AllPrinterEvents = [System.Collections.ArrayList]@()
            foreach ($printerEvent in $printerTaskEvents) {
                if ($printerEvent.Id -eq "300") { #look for event ID 300 -- "Add printer".  Should be unique for each printer
                    #check if this is a GUID
                    if ($printerEvent.Properties.Value -match("^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$")) {
                        foreach ($printerGUID in $UserPrinterGUIDs) {
                            Write-Debug "Searching for User Printer GUID: $($printerGUID.GuidPrinter)"
                            if ($printerGUID.GuidPrinter -eq $printerEvent.Properties.Value) {
                                #if printer has a GUID than it's a direct connection printer.  Capture its properties here
                                $printerName = $printerGUID.PSChildName -replace (",","\")
                                $printerGUIDValue = $printerEvent.Properties.Value
                                $printer = New-Object PSObject -property @{Name="$printerName";Value="$printerGUIDValue";Type="Direct Connection"}
                                Write-Verbose "Found Direct Connection Printer: $($printer)"
                                Write-Verbose "GUID: $($printerGUIDValue)"
                                $listOfPrinters += $printer

                                if ($SearchCommandLine) {
                                    Write-Verbose "We can search the command line for the print driver install events"
                                    #pull driver installation time -- requires 2012R2+ and command line capture policy enabled.
                                    $printDriverInstallationStartEvent = ($securityEvents|Where-Object { $_.Id -eq 4688 -and $_.TimeCreated -ge $logon.LogonTime -and $_.properties[$NewProcessName].Value -eq 'C:\Windows\System32\drvinst.exe' -and $_.properties[$CommandLine].Value -like "*$printerGUIDValue*" }) 
                                    $printDriverInstallationEndEvent = ($securityEvents|Where-Object { $_.Id -eq 4689 -and $_.TimeCreated -ge $logon.LogonTime -and $_.properties[$ProcessIdStop].Value -eq $printDriverInstallationStartEvent.Properties[$ProcessIdNew].Value -and $_.properties[$processName].Value -eq 'C:\Windows\System32\drvinst.exe'})
                                    Write-Verbose "New-TimeSpan -Start $($printDriverInstallationStartEvent.TimeCreated) -End $($printDriverInstallationEndEvent.TimeCreated)"
                                    $Duration = New-TimeSpan -Start $($printDriverInstallationStartEvent.TimeCreated) -End $($printDriverInstallationEndEvent.TimeCreated)
                                    $EventInfo = @{}
                                    $EventInfo.PhaseName = "    Driver : $printerName "
                                    $EventInfo.Duration = $Duration.TotalSeconds
                                    $EventInfo.EndTime = $printDriverInstallationEndEvent.TimeCreated
                                    $EventInfo.StartTime = $printDriverInstallationStartEvent.TimeCreated
                                    $AllPrinterEvents +=  New-Object -TypeName PSObject -Property $EventInfo
                                    Write-Debug "Post event creation"
                                    $PSObject = New-Object -TypeName PSObject -Property $EventInfo
        
                                    if ($EventInfo.Duration) {
                                        Write-Verbose "Adding driver phase to Output"
                                        $Script:Output += $PSObject
                                    }
                                }
                            }
                        }
                        foreach ($PrinterClientSidePortGUID in $PrinterClientSidePortGUIDs) {
                            Write-Debug "Searching for Printer Client Side Port GUID: $($PrinterClientSidePortGUID.PSChildName)"
                            if ($PrinterClientSidePortGUID.PSChildName -eq $printerEvent.Properties.Value) {
                                #we've found a printer client side port match.  This maybe due to a user reconnecting and the GUID's change on reconnect.
                                #the client side port registry keys contain the path to the real printer key
                                Write-Verbose "Client side port printer path: $($PrinterClientSidePortGUID.PrinterPath)"
                                $printerPath = ($PrinterClientSidePortGUID.PrinterPath -replace "\\Users\\$($Logon.UserSID)\\Printers\\","" -replace "\^","")
                                foreach ($printerGUID in $UserPrinterGUIDs) {
                                    $printerName = $printerGUID.PSChildName -replace (",","\")
                                    Write-Debug "Searching for Printer Name Match: $printerName"
                                    if ($printerName -eq $printerPath) {
                                        Write-Verbose "Found a Match: $printerName"
                                        #check to see if we captured this previously
                                        if (-not($listOfPrinters.Name -contains $printerPath)) {
                                            #if printer has a GUID than it's a direct connection printer.  Capture its properties here
                                            $printerGUIDValue = $printerEvent.Properties.Value
                                            $printer = New-Object PSObject -property @{Name="$printerName";Value="$printerGUIDValue";Type="Direct Connection"}
                                            Write-Verbose "Found Direct Connection Printer: $($printer)"
                                            Write-Verbose "GUID: $($printerGUIDValue)"
                                            $listOfPrinters += $printer

                                            if ($SearchCommandLine) {
                                                Write-Verbose "We can search the command line for the print driver install events"
                                                #pull driver installation time -- requires 2012R2+ and command line capture policy enabled.
                                                $printDriverInstallationStartEvent = ($securityEvents|Where-Object { $_.Id -eq 4688 -and $_.TimeCreated -ge $logon.LogonTime -and $_.properties[$NewProcessName].Value -eq 'C:\Windows\System32\drvinst.exe' -and $_.properties[$CommandLine].Value -like "*$printerGUIDValue*" }) 
                                                $printDriverInstallationEndEvent = ($securityEvents|Where-Object { $_.Id -eq 4689 -and $_.TimeCreated -ge $logon.LogonTime -and $_.properties[$ProcessIdStop].Value -eq $printDriverInstallationStartEvent.Properties[$ProcessIdNew].Value -and $_.properties[$processName].Value -eq 'C:\Windows\System32\drvinst.exe'})
                                                Write-Verbose "New-TimeSpan -Start $($printDriverInstallationStartEvent.TimeCreated) -End $($printDriverInstallationEndEvent.TimeCreated)"
                                                $Duration = New-TimeSpan -Start $($printDriverInstallationStartEvent.TimeCreated) -End $($printDriverInstallationEndEvent.TimeCreated)
                                                $EventInfo = @{}
                                                $EventInfo.PhaseName = "    Driver : $printerName "
                                                $EventInfo.Duration = $Duration.TotalSeconds
                                                $EventInfo.EndTime = $printDriverInstallationEndEvent.TimeCreated
                                                $EventInfo.StartTime = $printDriverInstallationStartEvent.TimeCreated
                                                $AllPrinterEvents +=  New-Object -TypeName PSObject -Property $EventInfo
                                                Write-Verbose "Post event creation"
                                                $PSObject = New-Object -TypeName PSObject -Property $EventInfo
        
                                                if ($EventInfo.Duration) {
                                                    Write-Verbose "Adding driver phase to Output"
                                                    $Script:Output += $PSObject
                                                }
                                            }
                                        }
                                    }
                                }
                                ########################################################################

                            }
                    }
                   } else {
                        #printer is a regular mapped printer.  Capture its properties here
                        #check client name in case there were concurrent logons to ensure we're targetting just events from this user
                        if( ! [string]::IsNullOrEmpty( $clientName ) ) {
                            if ($printerEvent.Message -like "*$clientName*") {
                                $printerName = ($printerEvent.Message -split "Printer " -split " on " -split "\(from")[1]
                                $printer = New-Object PSObject -property @{Name="$printerName";Value="N/A";Type="Mapped"}
                                Write-Verbose "Found Mapped Printer           : $($printer)"
                                $listOfPrinters += $printer
                            }
                        }
                    }
                }
            }

            foreach ($printer in $listOfPrinters) {
                $phaseName = "    Printer: $($printer.Name)"
                Write-Verbose "Phase: $phaseName"
                
                #capture each event 300 and 306 for the target printer.  There are further events 312 and 314 (add forms, deleting forms) that
                #occur for direct connection printers that is difficult to capture because the events lack targets, you can only do it via
                #date stamps.  Relying on that would be risky if there were concurrent logons, so we'll rely on the interim delay.
                $Events = [System.Collections.ArrayList]@()
                #foreach ($printerEvent in $printerTaskEvents) {
                foreach ($printerEvent in $printerTaskEvents | Where {($_.message -like "*$($printer.Name)*") -or ($_.message -like "*$($printer.Value)*")}) {
                    #$printerEvent
                    $Event = New-Object PSObject
                    $Event | Add-Member -membertype noteproperty -name TimeCreated -value $printerEvent.TimeCreated
                    $Event | Add-Member -membertype noteproperty -name Id -value $printerEvent.Id
                    $Events += $Event
                    Write-Verbose "Found $($printer.name)"
                    
                }
                write-Verbose "Events: $($events.count) for $($printer.name)" #this should be more than 1
                if ($events.count -gt 1) {
                    $Duration = New-TimeSpan -Start $($Events[-1].TimeCreated) -End $($Events[0].TimeCreated)
                    $EventInfo = @{}
                    $EventInfo.PhaseName = $PhaseName
                    $EventInfo.Duration = $Duration.TotalSeconds
                    $EventInfo.EndTime = $Events[0].TimeCreated
                    $EventInfo.StartTime = $Events[-1].TimeCreated
                    Clear-Variable Events
                    $PSObject = New-Object -TypeName PSObject -Property $EventInfo
                    $AllPrinterEvents +=  New-Object -TypeName PSObject -Property $EventInfo
                    if ($EventInfo.Duration) {
                        $Script:Output += $PSObject
                    }
                }
            }

            #capture the totality of the printer mapping sequence.
            if( $AllPrinterEvents -and $AllPrinterEvents.Count )
            {
                $Duration = New-TimeSpan -Start $($AllPrinterEvents.StartTime | sort -Descending)[-1] -End $($AllPrinterEvents.EndTime | sort -Descending)[0]
                $EventInfo = @{}
                $EventInfo.PhaseName = "  Connect to Printers"
                $EventInfo.Duration = $Duration.TotalSeconds
                $EventInfo.EndTime = ($AllPrinterEvents.EndTime | sort -Descending)[0]
                $EventInfo.StartTime = (($AllPrinterEvents.StartTime | sort -Descending)[-1]).AddMilliseconds(-10) #we subtract 5 milliseconds so the order sorts correctly
                $PSObject = New-Object -TypeName PSObject -Property $EventInfo
                if ($EventInfo.Duration) {
                        $Script:Output += $PSObject
                }
            }
            else
            {
                Write-Debug "No printer events found for client $ClientName"
            }
        }

        ## Set up runspacepool as we will parallelise some operations
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        
        ## need to import the functions we need from this module
        @( 'New-XPath' , 'Get-PhaseEvent' , 'Get-EventLogEnabledStatus' ) | ForEach-Object `
        {
            $function = $_
            $Definition = Get-Content Function:\$function -ErrorAction Continue
            $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $function , $Definition
            $sessionState.Commands.Add($SessionStateFunction)
        }

        $RunspacePool = [runspacefactory]::CreateRunspacePool(
            1, ## Min Runspaces
            10 , ## Max parallel runspaces ,
            $sessionstate ,
            $host
        )
        
        $sharedVars = [hashtable]::Synchronized(@{})
        $RunspacePool.Open()
        $tsevent = $null
        $logonEvent = $null
        $UserLogon = $null
        $wmiEvent = $null
        $jobs = New-Object System.Collections.ArrayList
        
        if( ! $offline )
        {
            $OS = Get-WmiObject -Class win32_operatingsystem -ErrorAction SilentlyContinue
            $CS = Get-WmiObject -Class win32_computersystem -ErrorAction SilentlyContinue
            if( $OS )
            {
                Write-Debug "OS is $($OS.Caption) $($OS.Version)"
            }
            if( $CS )
            {
                Write-Debug "Manufacturer $($CS.Manufacturer) model $($CS.Model), name $($CS.Name) domain $($CS.Domain) virtual $($CS.HypervisorPresent)"
            }
            ## this gives us logon time from LSA which is definitive
            Get-WmiObject win32_logonsession -Filter "LogonType='10' or LogonType='12' or LogonType='2' or LogonType='11'" | Sort StartTime -Desc | ForEach-Object `
            {
                $session = $_
 
                if( ! $wmiEvent -and $session.AuthenticationPackage -eq 'Kerberos' )
                {
                    Get-WmiObject win32_loggedonuser -filter "Dependent = '\\\\.\\root\\cimv2:Win32_LogonSession.LogonId=`"$($session.logonid)`"'" | ForEach-Object `
                    {
                        if( ! $wmiEvent -and $_.Antecedent -match 'Domain="(.*)",Name="(.*)"$' `
                            -and $matches -and $matches.Count -eq 3 -and $UserDomain -eq $matches[1] -and $userName -eq $matches[2] )
                        {
                            $wmiEvent = [pscustomobject]@{ 'LogonTime' = (([WMI] '').ConvertToDateTime( $session.StartTime )) ; 'LogonType' = $session.LogonType ; 'LogonId' = $session.LogonId }
                        }
                    }
                }
            }
        
            if( ! $wmiEvent )
            {
                ## Not fatal as we will fallback to other methods
                Write-Warning "Could not find win32_logonsession/win32_loggedonuser object for $UserDomain\$Username"
            }
        }

        try {
            ## Security event on its own happens on reconnect too so we use this log to find session so security event will be before this
            $tsevent = Get-WinEvent -MaxEvents 1 @global:terminalServicesParams  -FilterXPath (
                New-XPath -EventId 21 `
                -UserData @{
                    User="$UserDomain\$UserName"
                }) -ErrorAction Stop -Verbose:$False
        }
        catch [System.UnauthorizedAccessException] {
            Throw 'Unauthorized Operation, Please run the script with administrative privileges.'
        }
        catch {
            [string]$eventLogStatus = Get-EventLogEnabledStatus -eventLog 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
            if( ! [string]::IsNullOrEmpty( $eventLogStatus ) )
            {
                $PSCmdlet.WriteWarning( $eventLogStatus )
            }
            $oldest = Get-WinEvent -MaxEvents 1 -ProviderName Microsoft-Windows-TerminalServices-LocalSessionManager -Oldest -ErrorAction SilentlyContinue
            [string]$exceptionString = "Could not find EventID 21 (Session logon succeeded) in the Terminal Services Remote Desktop Services log"
            if( $oldest )
            {
                $exceptionString += ", oldest event is from $(Get-Date $oldest.TimeCreated -Format G)"
            }
            else
            {
                $exceptionString += ", could not find any events"
            }
            Throw $exceptionString
        }

        if ($global:windowsMajorVersion -ge 10) {
            [hashtable]$parameters = @{
                'UserName' = $userName
                'UserDomain' = $UserDomain
                'TSevent' = $tsevent
                'securityEventSource' = $global:securityParams
                'tsEventSource' = $global:terminalServicesParams
                'EncodeXpath' = ! $offline ## for reasons as yet unknown Microsoft-Windows-TerminalServices-LocalSessionManager log needs >= & <= encoding unlike all other logs but only when online
                }                
            $PowerShell = [PowerShell]::Create() 
            $PowerShell.RunspacePool = $RunspacePool
            [void]$PowerShell.AddScript({
                Param( $userName , $userDomain , $tsevent , [hashtable]$securityEventSource , [hashtable]$tsEventSource )
                try {
                    [hashtable]$eventData = @{
                                TargetUserName=$UserName
                                TargetDomainName=$UserDomain
                                LogonType=@(2,10,11,12)
                                ProcessName='C:\Windows\System32\svchost.exe'
                            }
                    if( $wmiEvent )
                    {
                        $eventData.Add( 'TargetLogonId' , $wmiEvent.LogonId )
                    }
                    Get-WinEvent -MaxEvents 1 @securityEventSource -FilterXPath (
                            New-XPath -EventId 4624 `
                            -ToDate $tsevent.TimeCreated `
                            -FromDate (Get-Date $tsevent.TimeCreated).AddSeconds( -300 ) `
                            -EventData $eventData ) -ErrorAction Stop -Verbose:$False
                }
                catch [System.UnauthorizedAccessException] {
                    Throw 'Unauthorized Operation, Please run the script with administrative privileges.'
                }
                catch {
                    $oldest = Get-WinEvent -MaxEvents 1 @securityEventSource -Oldest -ErrorAction SilentlyContinue
                    [string]$info = "Could not find EventID 4624 (Successfully logged on event) in the Windows Security log"
                    if( $oldest )
                    {
                        $info += " - oldest event is from $(Get-Date $oldest.TimeCreated -Format G)"
                    }
                    $info += Get-UserLogonDetails $Username
                    if( $auditingWarning )
                    {
                        $info += "`n$auditingWarning"
                        $auditingWarning = $null ## stop multiple occurrences
                    }
                    Throw $info
                }
            })
            [void]$PowerShell.AddParameters( $Parameters )
            [void]$jobs.Add( [pscustomobject]@{ 'PowerShell' = $PowerShell ; 'Handle' = $PowerShell.BeginInvoke() ; 'Name' = 'UserLogon' } )
            
            ## This is unreliable as will catch reconnects and flags as new logon unless we impose a time window

            $PowerShell = [PowerShell]::Create() 
            $PowerShell.RunspacePool = $RunspacePool
            [void]$PowerShell.AddScript({
                Param( $userName , $userDomain , $tsevent , [hashtable]$securityEventSource , [hashtable]$tsEventSource , $encodeXPath )
                try {
                    ## 'Begin session arbitration' but happens before event id 21 'Remote Desktop Services: Session logon succeeded' so we must search around that time
                    $LSMEvent = Get-WinEvent -MaxEvents 1 @tsEventSource -FilterXPath (
                        New-XPath -EventId 41 -UserData @{User="$UserDomain\$UserName"} `
                        -ToDate $tsevent.TimeCreated -encode:$encodeXPath `
                        -FromDate (Get-Date $tsevent.TimeCreated).AddSeconds( -300 ) ) `
                            -ErrorAction Stop -Verbose:$False

                    if( $LSMEvent )
                    {
                        $SessionId = $LSMEvent.Properties[1].Value
                
                        if( ! [string]::IsNullOrEmpty( $SessionId ) )
                        {
                            Get-WinEvent -MaxEvents 1 @securityEventSource -FilterXPath (
                                New-XPath -EventId 4624 `
                                -ToDate $tsevent.TimeCreated `
                                -FromDate (Get-Date $tsevent.TimeCreated).AddSeconds( -300 ) `
                                -EventData @{
                                    LogonType=2
                                    ProcessName='C:\Windows\System32\winlogon.exe'
                                    TargetUserName="DWM-$SessionId"
                                }) -ErrorAction Stop -Verbose:$False
                        }
                        else
                        {
                            Throw 'Could not find session id in EventID 41 (Begin session arbitration) in the TerminalServices-LocalSessionManager log.'
                        }
                    }
                    else
                    {
                        Throw 'Could not find EventID 41 (Begin session arbitration) in the TerminalServices-LocalSessionManager log.'
                    }
                }
                catch [System.UnauthorizedAccessException] {
                    Throw 'Unauthorized Operation, Please run the script with administrative privileges.'
                }
                catch {
                    Throw $_
                }
            })
            [void]$PowerShell.AddParameters( $Parameters )
            [void]$jobs.Add( [pscustomobject]@{ 'PowerShell' = $PowerShell ; 'Handle' = $PowerShell.BeginInvoke() ; 'Name' = 'LogonEvent' } )

            $jobs | ForEach-Object `
            {
                $job = $_
                try {
                    $result = $_.powershell.EndInvoke($_.handle)
                    if( $_.Name -eq 'LogonEvent' )
                    {
                        $logonEvent = $result
                    }
                    elseif( $_.Name -eq 'UserLogon' )
                    {
                        $UserLogon = $result
                    }
                }
                catch
                {
                    Write-Debug "Job $($job.Name) threw exception: $_"
                }
                $_.PowerShell.Dispose()
            }
            $jobs.clear()
            if( ! $logonEvent )
            {
                $logonEvent = $UserLogon
                $UserLogon = $null
            }
        }
        else {
            try {
                $LogonEvent = Get-WinEvent -MaxEvents 1 @securityParams -FilterXPath (
                New-XPath -EventId 4624 `
                    -ToDate $tsevent.TimeCreated `
                    -FromDate (Get-Date $tsevent.TimeCreated).AddSeconds( -300 ) `
                    -EventData @{
                        TargetUserName=$UserName
                        TargetDomainName=$UserDomain
                        LogonType=@(2,10,11)
                        ProcessName='C:\Windows\System32\winlogon.exe'
                    }) -ErrorAction Stop -Verbose:$False
            }
            catch [System.UnauthorizedAccessException] {
                Throw 'Unauthorized Operation, Please run the script with administrative privileges.'
            }
            catch {
                $oldest = Get-WinEvent -MaxEvents 1 @securityParams -Oldest

                [string]$info = "Could not find EventID 4624 (Successfully logged on event) in the Windows Security log"
                if( $oldest )
                {
                    $info += " - oldest event is from $(Get-Date $oldest.TimeCreated -Format G)"
                }
                $info += Get-UserLogonDetails $Username
                
                if( $auditingWarning )
                {
                    $info += "`n$auditingWarning"
                    $auditingWarning = $null ## stop multiple occurrences
                }

                Throw $info
            }
        }

        if( ! $LogonEvent )
        {
            [string]$exception = "Failed to find the logon event for $Username $(Get-UserLogonDetails $username)"
            [hashtable]$params =  if( $offline ) { $securityParams } else { @{ 'LogName' = 'Security' } }
            $oldest = Get-WinEvent -MaxEvents 1 @params -Oldest   
            if( $oldest )
            {
                $exception += "`nOldest security event is from $(Get-Date $oldest.TimeCreated -Format G)"
                if( $oldest.Id -eq 1102 )
                {
                    $exception += ( " when {0} by {1}\{2}" -f ($oldest.Message -split "[\.`n]")[0].ToString().ToLower() , $oldest.Properties[2].Value , $oldest.Properties[1].Value )
                }
            }
            $securityEventLog = Get-WinEvent -ListLog 'Security'
            if( $securityEventLog )
            {
                [int]$sizeInMB = [math]::Round($securityEventLog.MaximumSizeInBytes / 1MB , 1)
                $exception += "`nSecurity event log maximum size is $($sizeInMB)MB"
                if( $sizeInMB -lt $suggestedSecurityEventLogSizeMB )
                {
                    $exception += ". You may want to increase this to at least $($suggestedSecurityEventLogSizeMB)MB"
                }
                if( $oldest )
                {
                    $newest = Get-WinEvent -MaxEvents 1 -LogName 'Security'
                    if( $newest )
                    {
                        $timespan = New-TimeSpan -Start $oldest.TimeCreated -End $newest.TimeCreated
                        $exception += ( "`nSecurity event log currently contains {0} records over {1} days so an average rate of {2} events logged per day`n" -f $securityEventLog.RecordCount , [Math]::Round( $timespan.TotalDays , 1 ) , [Math]::Round( $securityEventLog.RecordCount / $timespan.TotalDays , 1) )
                    }
                }
            }
            
            if( $auditingWarning )
            {
                $exception += "`n$auditingWarning"
                $auditingWarning = $null ## stop multiple occurrences
            }

            Throw $exception
        }

        if ($UserLogon) {
            $Logon = New-Object -TypeName psobject -Property @{
                LogonTime = $LogonEvent.TimeCreated
                FormatTime = (Get-Date -Date $LogonEvent.TimeCreated -UFormat %r)
                WinlogonPID = ($LogonEvent.Properties[16]).Value
                LogonID = ($UserLogon.Properties[7]).Value
                UserSID = ($UserLogon.Properties[4]).Value
                Type = ($UserLogon.Properties[8]).Value
            }
        }
        else {
            $Logon = New-Object -TypeName psobject -Property @{
                LogonTime = $LogonEvent.TimeCreated
                FormatTime = (Get-Date -Date $LogonEvent.TimeCreated -UFormat %r)
                WinlogonPID = ($LogonEvent.Properties[16]).Value
                LogonID = ($LogonEvent.Properties[7]).Value
                UserSID = ($LogonEvent.Properties[4]).Value
                Type = ($LogonEvent.Properties[8]).Value
            }
        }
        if( $wmiEvent )
        {
            $Logon.LogonTime = $wmiEvent.LogonTime
            $logon.FormatTime = '{0:HH:mm:ss.f}' -f $Logon.LogonTime ## show tenths of second since durations are displayed that way
        }
        Write-Debug "Logon data: $Logon"
    }

    process {          
            [hashtable]$parameters = @{
                'UserName' = $userName
                'UserDomain' = $UserDomain
                'Logon' = $logon
                'SharedVars' = $sharedVars
                'UserProfileEventFile' = $global:userProfileParams[ 'Path' ]
                'GroupPolicyEventFile' = $global:groupPolicyParams[ 'Path' ]
                'CitrixUPMEventFile'   = $global:citrixUPMParams[ 'Path' ]
             }

        # If the machine is a Citrix VDA and a Session ID is provided, look for "HDX Connection" Phase
        $odataPhase = $null
        if( $offline )
        {
            Write-Debug "Skipping HDX check as in offline mode"
        }
        else
        {
            if ((Get-Service -Name BrokerAgent -ErrorAction SilentlyContinue) -and ($HDXSessionId)  ) {
                if ($XDUsername -and $XDPassword) {
                    $odataPhase = Get-ODataPhase
                }
                else {
                    Write-Host "INFO: No credentials entered for the XenDesktop username/password fields"
                }
            }
        }
        [hashtable]$securityFilter = @{StartTime=$logon.LogonTime;EndTime=($logon.LogonTime.AddMinutes( 60 ));Id=4018,5018,4688,4689}
        if( $securityParams[ 'Path' ] )
        {
            $securityFilter.Add( 'Path' , $securityParams[ 'Path' ] )
        }
        else
        {
            $securityFilter.Add( 'LogName' , 'Security' )
        }
        [array]$securityEvents = @( Get-WinEvent -FilterHashtable $securityFilter -ErrorAction SilentlyContinue)
        if( ! $securityEvents -or ! $securityEvents.Count )
        {
            Write-Warning "Failed to cache any relevant security event logs from $(Get-Date $logon.LogonTime -Format G) for 60 minutes"
        }

        ## only seem to get this when RDS role is installed (Multi-user Win10 or Server OS)
        if( ! $offline -and (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Compatibility' -ErrorAction SilentlyContinue) )
        {
            $networkStartEvent = ($securityEvents|Where-Object { $_.Id -eq 4688 -and $_.TimeCreated -ge $logon.LogonTime -and $_.Properties[$ProcessIdStart].value -eq $Logon.WinlogonPID -and $_.properties[$NewProcessName].Value -eq 'C:\Windows\System32\mpnotify.exe' } | Select -Last 1 )
            if( $networkStartEvent )
            {
                $Script:Output += Get-PhaseEventFromCache -PhaseName 'Network Providers' `
                    -startEvent $networkStartEvent `
                    -endEvent ($securityEvents|Where-Object { $_.Id -eq 4689 -and $_.TimeCreated -ge $networkStartEvent.TimeCreated -and $_.Properties[$ProcessIdStop].value -eq $networkStartEvent.Properties[$ProcessIdNew].Value -and $_.properties[$ProcessName].Value -eq 'C:\Windows\System32\mpnotify.exe' } | Select -Last 1)
            }
            else
            {
                [string]$warning = "Unable to find network providers start event"
                if( $auditingWarning )
                {
                    $warning += "`n$auditingWarning"
                    $auditingWarning = $null ## stop multiple occurrences
                }
                Write-Warning $warning
            }
        }

        if ( $global:citrixUPMParams[ 'Path' ] -or ( Get-WinEvent -ListProvider 'Citrix Profile management' -ErrorAction SilentlyContinue)) {
            ($PowerShell = [PowerShell]::Create()).RunspacePool = $RunspacePool

            [scriptblock]$citrixScriptBlock = $null
            if( $global:citrixUPMParams[ 'Path' ] )
            {
                $citrixScriptBlock =
                {
                    Param( $logon , $username , $CitrixUPMEventFile , $UserProfileEventFile )
                    Get-PhaseEvent -PhaseName 'Citrix Profile Mgmt' -StartProvider 'Citrix Profile management' `
                        -StartEventFile $CitrixUPMEventFile `
                        -EndEventFile $UserProfileEventFile `
                        -EndProvider 'Microsoft-Windows-User Profiles Service' -StartXPath (
                        New-XPath -EventId 10 -From (Get-Date -Date $Logon.LogonTime) `
                         -EventData $UserName) -EndXPath (
                        New-XPath -EventId 1 -From (Get-Date -Date $Logon.LogonTime) `
                         -SecurityData @{
                             UserID=$Logon.UserSID
                    })
                }
            }
            else ## online
            {
                $citrixScriptBlock =
                {
                    Param( $logon , $username )
                    Get-PhaseEvent -PhaseName 'Citrix Profile Mgmt' -StartProvider 'Citrix Profile management' `
                        -EndProvider 'Microsoft-Windows-User Profiles Service' -StartXPath (
                        New-XPath -EventId 10 -From (Get-Date -Date $Logon.LogonTime) `
                            -EventData $UserName) -EndXPath (
                        New-XPath -EventId 1 -From (Get-Date -Date $Logon.LogonTime) `
                         -SecurityData @{
                             UserID=$Logon.UserSID
                    })
                }
            }
            [void]$PowerShell.AddScript( $citrixScriptBlock )
            [void]$PowerShell.AddParameters( $Parameters )
            [void]$jobs.Add( [pscustomobject]@{ 'PowerShell' = $PowerShell ; 'Handle' = $PowerShell.BeginInvoke() } )
        }

        ($PowerShell = [PowerShell]::Create()).RunspacePool = $RunspacePool

        [scriptblock]$scriptBlock = $null
        if( $global:userProfileParams[ 'Path' ] )
        {
            $scriptBlock = `
            {
                Param( $logon , $UserProfileEventFile )
                Get-PhaseEvent -PhaseName 'User Profile' `
                    -StartEventFile $UserProfileEventFile `
                    -EndEventFile $UserProfileEventFile `
                    -eventLog 'Microsoft-Windows-User Profile Service/Operational' `
                    -StartProvider 'Microsoft-Windows-User Profiles Service' `
                    -EndProvider 'Microsoft-Windows-User Profiles Service' `
                    -StartXPath (New-XPath -EventId 1 -From (Get-Date -Date $Logon.LogonTime) `
                    -SecurityData @{UserID=$Logon.UserSID}) `
                    -EndXPath (New-XPath -EventId 2 -From (Get-Date -Date $Logon.LogonTime) `
                    -SecurityData @{
                        UserID=$Logon.UserSID
                    })
            }
        }
        else ## online
        {
            $scriptBlock = `
            {
                Param( $logon )
                Get-PhaseEvent -PhaseName 'User Profile' `
                    -eventLog 'Microsoft-Windows-User Profile Service/Operational' `
                    -StartProvider 'Microsoft-Windows-User Profiles Service' `
                    -EndProvider 'Microsoft-Windows-User Profiles Service' `
                    -StartXPath (New-XPath -EventId 1 -From (Get-Date -Date $Logon.LogonTime) `
                    -SecurityData @{UserID=$Logon.UserSID}) `
                    -EndXPath (New-XPath -EventId 2 -From (Get-Date -Date $Logon.LogonTime) `
                    -SecurityData @{
                        UserID=$Logon.UserSID
                    })
            }
        }
        [void]$PowerShell.AddScript( $scriptBlock )
        [void]$PowerShell.AddParameters( $Parameters )
        [void]$jobs.Add( [pscustomobject]@{ 'PowerShell' = $PowerShell ; 'Handle' = $PowerShell.BeginInvoke() } )
        
        ($PowerShell = [PowerShell]::Create()).RunspacePool = $RunspacePool

        [scriptblock]$groupPolicyScriptBlock = $null
        if( $global:groupPolicyParams[ 'Path' ] )
        {
            $groupPolicyScriptBlock = {
                Param( $logon , $Username , $UserDomain , $groupPolicyEventFile )
                Get-PhaseEvent -PhaseName 'Group Policy' `
                    -StartEventFile $groupPolicyEventFile `
                    -EndEventFile $groupPolicyEventFile `
                    -eventLog 'Microsoft-Windows-GroupPolicy/Operational' `
                    -StartProvider 'Microsoft-Windows-GroupPolicy' `
                    -EndProvider 'Microsoft-Windows-GroupPolicy' `
                    -StartXPath (
                    New-XPath -EventId 4001 -From (Get-Date -Date $Logon.LogonTime) `
                    -EventData @{
                        PrincipalSamName="$UserDomain\$UserName"
                    }) -EndXPath (
                    New-XPath -EventId 8001 -From (Get-Date -Date $Logon.LogonTime) `
                    -EventData @{
                        PrincipalSamName="$UserDomain\$UserName"
                    })
             }
        }
        else
        {
            $groupPolicyScriptBlock = {
                Param( $logon , $Username , $UserDomain )
                Get-PhaseEvent -PhaseName 'Group Policy' `
                    -eventLog 'Microsoft-Windows-GroupPolicy/Operational' `
                    -StartProvider 'Microsoft-Windows-GroupPolicy' `
                    -EndProvider 'Microsoft-Windows-GroupPolicy' `
                    -StartXPath (
                    New-XPath -EventId 4001 -From (Get-Date -Date $Logon.LogonTime) `
                    -EventData @{
                        PrincipalSamName="$UserDomain\$UserName"
                    }) -EndXPath (
                    New-XPath -EventId 8001 -From (Get-Date -Date $Logon.LogonTime) `
                    -EventData @{
                        PrincipalSamName="$UserDomain\$UserName"
                    })
            }
        }
         
        [void]$PowerShell.AddScript( $groupPolicyScriptBlock )
        [void]$PowerShell.AddParameters( $Parameters )
        [void]$jobs.Add( [pscustomobject]@{ 'PowerShell' = $PowerShell ; 'Handle' = $PowerShell.BeginInvoke() } )
        
        ($PowerShell = [PowerShell]::Create()).RunspacePool = $RunspacePool

        [scriptblock]$gpScriptBlock = $null
        if( $global:groupPolicyParams[ 'Path' ] )
        {
            $gpScriptBlock = 
            {
                Param( $logon , $UserDomain , $Username , $sharedVars , $groupPolicyEventFile )
                Get-PhaseEvent -PhaseName 'GP Scripts' -StartProvider 'Microsoft-Windows-GroupPolicy' -SharedVars $sharedVars `
                    -StartEventFile $groupPolicyEventFile `
                    -EndEventFile $groupPolicyEventFile `
                    -EndProvider 'Microsoft-Windows-GroupPolicy' `
                    -StartXPath (
                    New-XPath -EventId 4018 -From (Get-Date -Date $Logon.LogonTime) `
                    -EventData @{PrincipalSamName="$UserDomain\$UserName";ScriptType=1}) `
                    -EndXPath (
                    New-XPath -EventId 5018 -From (Get-Date -Date $Logon.LogonTime) `
                    -EventData @{
                        PrincipalSamName="$UserDomain\$UserName"
                        ScriptType=1
                    })
             }
        }
        else
        {
            $gpScriptBlock = 
            {
                Param( $logon , $UserDomain , $Username , $sharedVars )
                Get-PhaseEvent -PhaseName 'GP Scripts' -StartProvider 'Microsoft-Windows-GroupPolicy' -SharedVars $sharedVars `
                    -EndProvider 'Microsoft-Windows-GroupPolicy' `
                    -StartXPath (
                    New-XPath -EventId 4018 -From (Get-Date -Date $Logon.LogonTime) `
                    -EventData @{PrincipalSamName="$UserDomain\$UserName";ScriptType=1}) `
                    -EndXPath (
                    New-XPath -EventId 5018 -From (Get-Date -Date $Logon.LogonTime) `
                    -EventData @{
                        PrincipalSamName="$UserDomain\$UserName"
                        ScriptType=1
                    })
             }
        }
        [void]$PowerShell.AddScript( $gpScriptBlock )    
        [void]$PowerShell.AddParameters( $Parameters )
        [void]$jobs.Add( [pscustomobject]@{ 'PowerShell' = $PowerShell ; 'Handle' = $PowerShell.BeginInvoke() } )
        
        ($PowerShell = [PowerShell]::Create()).RunspacePool = $RunspacePool

        $userinitStartEvent = ($securityEvents|Where-Object { $_.Id -eq 4688 -and $_.TimeCreated -ge $logon.LogonTime -and $_.Properties[$TargetLogonId].value -eq $Logon.LogonId `
            -and $_.Properties[$TargetUserName ].value -eq $Username -and $_.Properties[$TargetDomainName ].value -eq $UserDomain -and $_.properties[$NewProcessName].Value -eq 'C:\Windows\System32\userinit.exe' } | Select -Last 1 ) 
        if( $userinitStartEvent )
        {
            $Script:Output += Get-PhaseEventFromCache -PhaseName 'Pre-Shell (Userinit)' `
                -startEvent $userinitStartEvent `
                -endEvent ($securityEvents|Where-Object { $_.Id -eq 4688 -and $_.TimeCreated -ge $logon.LogonTime -and $_.Properties[$SubjectLogonId].value -eq $Logon.LogonID -and ( $_.Properties[$NewProcessName].value -eq 'C:\Windows\explorer.exe' -or $_.Properties[$NewProcessName].value -eq 'C:\Program Files (x86)\Citrix\system32\icast.exe' ) } | Select -Last 1)
        }
        else
        {
            [string]$info = "Unable to find Pre-Shell (Userinit) start event"
            if( $auditingWarning )
            {
                $info += "`n$auditingWarning"
                $auditingWarning = $null ## stop multiple occurrences
            }
            Write-Warning $info
        }

        ## See if user has a login script in AD and if so look for start and end in process start/stop events
        $ADuser = ([ADSI]"WinNT://$UserDomain/$Username,user")
        if( $ADUser -and $ADuser.LoginScript )
        {
            if( $searchCommandLine -or $offline )
            {
                ## could be more than one since usrlogon.cmd may also be launched so need to check we have the right one although not checking down to which server as can't. Don't check for actual process as could be cmd, wscript, etc
                [string]$escapedLogonScript = [regex]::Escape( ( Join-Path -Path '\NETLOGON' -ChildPath ($ADuser.LoginScript.ToString()) ) )
                $logonScriptStartEvent = ($securityEvents|Where-Object { $_.Id -eq 4688 -and $_.TimeCreated -ge $logon.LogonTime -and $_.Properties[$SubjectUserName].value -eq $userName -and $_.Properties[$SubjectDomainName].value -eq $UserDomain `
                     -and $_.Properties[$CommandLine].value -match $escapedLogonScript -and $_.Properties[$ParentProcessName].value -eq 'C:\Windows\System32\userinit.exe' } ) | Select -Last 1
                if( $logonScriptStartEvent )
                {
                    $Script:Output += Get-PhaseEventFromCache -PhaseName 'User logon script' `
                        -startEvent $logonScriptStartEvent `
                        -endEvent ($securityEvents|Where-Object { $_.Id -eq 4689 -and $_.TimeCreated -ge $userinitStartEvent.TimeCreated -and $_.Properties[$ProcessIdStop].value -eq $logonScriptStartEvent.Properties[$ProcessIdNew].value -and $_.Properties[$SubjectLogonId].value -eq $logonScriptStartEvent.Properties[$SubjectLogonId].value } | Select -Last 1)
                }
            }
            else
            {
                $logonScriptStartEvent = $null
            }

            if( ! $logonScriptStartEvent )
            {
                [string]$warning = "Unable to find user logon script ($($ADUser.LoginScript)) start event"
                if( $auditingWarning )
                {
                    $warning += "`n$auditingWarning"
                    $auditingWarning = $null ## stop multiple occurrences
                }
                if( $commandLinePolicy -and $commandLinePolicy.ProcessCreationIncludeCmdLine_Enabled -ne 1 )
                {
                    $warning += ', "Command line process auditing" is not enabled'
                }
                Write-Warning $warning
            }
        }

        if ($CUDesktopLoadTime -gt 0 ) {
            $shellStartEvent = ($securityEvents|Where-Object { $_.Id -eq 4688 -and $_.TimeCreated -ge $logon.LogonTime -and $_.Properties[$SubjectLogonId].value -eq $Logon.LogonID -and $_.properties[$NewProcessName].Value -eq 'C:\Windows\explorer.exe' } | Select -Last 1 ) 
            if( $shellStartEvent )
            {
                $Script:Output += Get-PhaseEventFromCache -PhaseName 'Shell' -startEvent $shellStartEvent -CUAddition $CUDesktopLoadTime }
            else
            {
                [string]$warning = "Unable to find Shell start event"
                if( $auditingWarning )
                {
                    $warning += "`n$auditingWarning"
                    $auditingWarning = $null ## stop multiple occurrences
                }
                Write-Warning $warning
            }
        }
        
        $script:output += @( $jobs | ForEach-Object `
        {
            $_.powershell.EndInvoke($_.handle)
            $_.PowerShell.Dispose()
        })
        $jobs.clear()

        $Script:GPAsync = $sharedVars[ 'GPASync' ]
        if( $userinitStartEvent )
        {
            Write-Debug "Get-PrinterEvents -Start $($userinitStartEvent.TimeCreated) -End $(($Script:Output | Where {$_.PhaseName -eq 'Pre-Shell (Userinit)'}).EndTime) -ClientName $ClientName"
            $end = ($Script:Output | Where {$_.PhaseName -eq 'Pre-Shell (Userinit)'}) | Select-Object -ExpandProperty EndTime
            if( $end )
            {
                Get-PrinterEvents -Start $userinitStartEvent.TimeCreated -End $end -ClientName $ClientName
            }
        }

        if (($Script:Output).Length -lt 2 ) {
            $PSCmdlet.WriteWarning("Not enough data for that session, Aborting function...")
            Throw 'Could not find more than a single phase, script is aborted'
        }
    }
    end {
        $LogonTimeReal = $Logon.FormatTime
        $Script:Output = $Script:Output | Sort-Object StartTime
        $TotalDur = 'N/A'
        if ( $Script:LogonStartDate) { ## Not set any more, used to be via OData function
            $Script:LogonStartDate = $Script:LogonStartDate.ToLocalTime()
            ForEach( $phase in $script:output ) {
                if ($phase.PhaseName -eq 'Shell' -or $phase.PhaseName -eq 'Pre-Shell (Userinit)' ) {
                    [decimal]$thisDuration = New-TimeSpan -Start $Script:LogonStartDate -End $Script:Output[-1].EndTime | Select-Object -ExpandProperty TotalSeconds
                    if( $TotalDur -eq 'N/A' -or $TotalDur -as [decimal] -lt $thisDuration ) {
                        $TotalDur = $thisDuration
                    }
                }
            }
            $Deltas = New-TimeSpan -Start $Script:LogonStartDate -End $Script:Output[0].StartTime
            $Script:Output[0] | Add-Member -MemberType NoteProperty -Name TimeDelta -Value $Deltas -Force
            $LogonTimeReal =  (Get-Date -Date $Script:LogonStartDate -UFormat %r)
        }
        else {
            $TotalDur = 'N/A'
            ForEach( $phase in $script:output ) {
                if ($phase.PhaseName -eq 'Shell' -or $phase.PhaseName -eq 'Pre-Shell (Userinit)' ) {
                    [decimal]$thisDuration = New-TimeSpan -Start $Logon.LogonTime -End $phase.EndTime | Select-Object -ExpandProperty TotalSeconds
                    if( $TotalDur -eq 'N/A' -or $TotalDur -as [decimal] -lt $thisDuration ) {
                        $TotalDur = $thisDuration
                    }
                }
            }
            $Deltas = New-TimeSpan -Start $Logon.LogonTime -End $Script:Output[0].StartTime
            $Script:Output[0] | Add-Member -MemberType NoteProperty -Name TimeDelta -Value $Deltas -Force
        }
        for($i=1;$i -le $Script:Output.length-1;$i++) {
            $Deltas = New-TimeSpan -Start $Script:Output[$i-1].EndTime -End $Script:Output[$i].StartTime
            if ($Deltas -lt 0) {
                #if tasks are run asynchronously, then deltas may not be timed correctly.  Setting the value as blank to avoid confusion.
                $Deltas = ""
            }
            $Script:Output[$i] | Add-Member -MemberType NoteProperty -Name TimeDelta -Value $Deltas -Force
        }
        $LogonTaskList = Get-LogonTask -UserName $Username -UserDomain $UserDomain -Start $Logon.LogonTime -End $Script:Output[-1].EndTime

        $outputObject = [pscustomobject][ordered]@{ 'User name ' = $username }
        if( $odataPhase ) {
            Add-Member -InputObject $outputObject -MemberType NoteProperty -Name ( '{0} Time' -f $odataPhase.PhaseName ) -Value ( '{0:HH:mm:ss.f}' -f $odataPhase.StartTime )
            Add-Member -InputObject $outputObject -MemberType NoteProperty -Name ( '{0:N1} Duration' -f $odataPhase.PhaseName ) -Value ( '{0} seconds' -f $odataPhase.Duration )
        }
        Add-Member -InputObject $outputObject -MemberType NoteProperty -Name 'Logon Time' -Value $LogonTimeReal  
        Add-Member -InputObject $outputObject -MemberType NoteProperty -Name 'Logon Duration' -Value ( '{0:N1} seconds' -f $TotalDur )

        ($outputObject | Format-List | Out-String).Trim()
        Write-Output ''

        $Format = @{Expression={$_.PhaseName};Label="Logon Phase"}, `
                  @{Expression={'{0:N1}' -f $_.Duration};Label="Duration (s)"}, `
                  @{Expression={'{0:HH:mm:ss.f}' -f $_.StartTime};Label="Start Time"}, `
                  @{Expression={'{0:HH:mm:ss.f}' -f $_.EndTime};Label="End Time"}, `
                  @{Expression={'{0:N1}' -f ($_.TimeDelta | `
                    Select-Object -ExpandProperty TotalSeconds)};Label="Interim Delay"}
        
        ($Script:Output | Format-Table $Format -AutoSize | Out-String).Trim()

        if ($Script:GPAsync) {
            "Group Policy asynchronous scripts were processed for $Script:GPAsync seconds"
        }
        $LogonTaskList | Format-Table @{Expression={$_.TaskName};Label="Logon Sched. Task"},@{Expression={'{0:s\.ff}' -f $_.Duration};Label="Duration (s)"},@{Expression={$_.ActionName};Label="Action Name"} -AutoSize
    }
}

# Altering the size of the PS Buffer
$PSWindow = (Get-Host).UI.RawUI
$WideDimensions = $PSWindow.BufferSize
$WideDimensions.Width = $outputWidth
$PSWindow.BufferSize = $WideDimensions

#region Get local session information
$TSSessions = @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
public class RDPInfo
{
    [DllImport("wtsapi32.dll")]
    static extern IntPtr WTSOpenServer([MarshalAs(UnmanagedType.LPStr)] String pServerName);

    [DllImport("wtsapi32.dll")]
    static extern void WTSCloseServer(IntPtr hServer);

    [DllImport("wtsapi32.dll")]
    static extern Int32 WTSEnumerateSessions(
        IntPtr hServer,
        [MarshalAs(UnmanagedType.U4)] Int32 Reserved,
        [MarshalAs(UnmanagedType.U4)] Int32 Version,
        ref IntPtr ppSessionInfo,
        [MarshalAs(UnmanagedType.U4)] ref Int32 pCount);

    [DllImport("wtsapi32.dll")]
    static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("Wtsapi32.dll")]
    static extern bool WTSQuerySessionInformation(System.IntPtr hServer, int sessionId, WTS_INFO_CLASS wtsInfoClass, out System.IntPtr ppBuffer, out uint pBytesReturned);

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
        public Int32 SessionID;
        [MarshalAs(UnmanagedType.LPStr)]
        public String pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    public enum WTS_INFO_CLASS
    {
        WTSInitialProgram,
        WTSApplicationName,
        WTSWorkingDirectory,
        WTSOEMId,
        WTSSessionId,
        WTSUserName,
        WTSWinStationName,
        WTSDomainName,
        WTSConnectState,
        WTSClientBuildNumber,
        WTSClientName,
        WTSClientDirectory,
        WTSClientProductId,
        WTSClientHardwareId,
        WTSClientAddress,
        WTSClientDisplay,
        WTSClientProtocolType
    }

    public enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive,
        WTSConnected,
        WTSConnectQuery,
        WTSShadow,
        WTSDisconnected,
        WTSIdle,
        WTSListen,
        WTSReset,
        WTSDown,
        WTSInit
    }

    public static IntPtr OpenServer(String Name)
    {
        IntPtr server = WTSOpenServer(Name);
        return server;
    }

    public static void CloseServer(IntPtr ServerHandle)
    {
        WTSCloseServer(ServerHandle);
    }

    public static List<string> ListUsers(String ServerName)
    {
        IntPtr serverHandle = IntPtr.Zero;
        List<String> resultList = new List<string>();
        serverHandle = OpenServer(ServerName);

        try
        {
            IntPtr SessionInfoPtr = IntPtr.Zero;
            IntPtr userPtr = IntPtr.Zero;
            IntPtr domainPtr = IntPtr.Zero;
            IntPtr clientNamePtr = IntPtr.Zero;
            IntPtr winStationNamePtr = IntPtr.Zero;
            Int32 sessionCount = 0;
            Int32 retVal = WTSEnumerateSessions(serverHandle, 0, 1, ref SessionInfoPtr, ref sessionCount);
            Int32 dataSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
            IntPtr currentSession = (IntPtr)SessionInfoPtr;
            uint bytes = 0;

            if (retVal != 0)
            {
                for (int i = 0; i < sessionCount; i++)
                {
                    WTS_SESSION_INFO si = (WTS_SESSION_INFO)Marshal.PtrToStructure((System.IntPtr)currentSession, typeof(WTS_SESSION_INFO));
                    currentSession += dataSize;
                    

                    WTSQuerySessionInformation(serverHandle, si.SessionID, WTS_INFO_CLASS.WTSUserName, out userPtr, out bytes);
                    WTSQuerySessionInformation(serverHandle, si.SessionID, WTS_INFO_CLASS.WTSDomainName, out domainPtr, out bytes);
                    WTSQuerySessionInformation(serverHandle, si.SessionID, WTS_INFO_CLASS.WTSClientName, out clientNamePtr, out bytes);
                    WTSQuerySessionInformation(serverHandle, si.SessionID, WTS_INFO_CLASS.WTSWinStationName, out winStationNamePtr, out bytes);

                    if(Marshal.PtrToStringAnsi(domainPtr).Length > 0 && Marshal.PtrToStringAnsi(userPtr).Length > 0)
                    {
                        if(Marshal.PtrToStringAnsi(clientNamePtr).Length < 1)                       
                            resultList.Add("UserName:" + Marshal.PtrToStringAnsi(domainPtr) + "\\" + Marshal.PtrToStringAnsi(userPtr) + "\tSessionID:" + si.SessionID + "\tClientName:N/A" + "\tSessionName:N/A");
                        else
                            resultList.Add("UserName:" + Marshal.PtrToStringAnsi(domainPtr) + "\\" + Marshal.PtrToStringAnsi(userPtr) + "\tSessionID:" + si.SessionID + "\tClientName:" + Marshal.PtrToStringAnsi(clientNamePtr) + "\tSessionName:" + Marshal.PtrToStringAnsi(winStationNamePtr));
                    }
                    WTSFreeMemory(clientNamePtr);
                    WTSFreeMemory(userPtr);
                    WTSFreeMemory(domainPtr);
                }
                WTSFreeMemory(SessionInfoPtr);
            }
        }
        catch(Exception ex)
        {
            Console.WriteLine("Exception: " + ex.Message);
            resultList.Add("Exception: " + ex.Message);
        }
        finally
        {
            CloseServer(serverHandle);
            
        }
        return resultList;
    }
}
'@

#here we sort out the parameters.  There is an issue with some parameters not being passed so we need to run some checks and validate them.
$args_fix = ($args[0] -split '\\')
$UserName = $args_fix[1]
$UserDomain = $args_fix[0]
$SessionId = $(if( $args.Count -ge 3) { $args[2] })
$XDUsername = $null
$XDPassword = $null

$foundAllParameters = $false

if( ! $offline )
{
    Add-Type $TSSessions

    $sessionInfo = [RDPInfo]::listUsers("localhost")
    $sessionArray = @()

    #converts Output from pInvoke to PowerShell Object
    foreach ($line in $sessionInfo) {
        $sessionInfoObject = New-Object System.Object
        foreach ($object in ($line -split "\t")) {
    
            if ($object -like "*UserName*") { Write-Debug "Username: $object"
                $sessionInfoObject | Add-Member -type NoteProperty -name UserName -value ($object -split ":")[1] }
            if ($object -like "*SessionID*") { Write-Debug "SessionID: $object"
                $sessionInfoObject | Add-Member -type NoteProperty -name SessionID -value ($object -split ":")[1] }
            if ($object -like "*ClientName*") { Write-Debug "ClientName: $object"
                $sessionInfoObject | Add-Member -type NoteProperty -name ClientName -value ($object -split ":")[1] }
            if ($object -like "*SessionName*") { Write-Debug "SessionName: $object"
                $sessionInfoObject | Add-Member -type NoteProperty -name SessionName -value ($object -split ":")[1] }
        }
        $sessionArray += $sessionInfoObject
    
    }
    #endregion

    foreach ($session in $sessionArray) {
        try {
            if ($session.Username -eq $args[0] -and $session.SessionId -eq $args[2] -and $session.ClientName -eq $args[4] -and $session.SessionName -eq $args[3] ) {
                Write-Verbose "All session parameters found"
                $SessionName = $args[3]
                $ClientName = $args[4]
                $foundAllParameters = $true
            }
        }
        catch {
            ## not all parameters are required when run manually
        }
    }
}

if (-not($foundAllParameters)) {
    Write-Verbose "Only partial parameters found"
    $UserTest = $args[0]
    $count = $sessionArray | Where-Object -FilterScript { $_.UserName -eq $UserTest } | Select -ExpandProperty Count -ErrorAction SilentlyContinue
    Write-Verbose "Found $count number of sessions for $($args[0])"
    if ($count -eq 1) {
        $ClientName = ($sessionArray | Where-Object -FilterScript { $_.UserName -eq $UserTest }).ClientName
        $SessionName = ($sessionArray | Where-Object -FilterScript { $_.UserName -eq $UserTest }).SessionName
        $SessionId = ($sessionArray | Where-Object -FilterScript { $_.UserName -eq $UserTest }).SessionId
    } else {
        $SessionName = $null
        $clientName = $null
    }
}

Write-Debug "UTC offset is $([System.TimeZone]::CurrentTimeZone.GetUtcOffset(0)|Select-Object -ExpandProperty TotalMinutes) minutes"

## if we have extra parameters then let's go into debug mode - must be used with XenDesktop credentials even if dummy until support for null parameters arrives
if( $args.Count -gt 7 -or $env:CONTROLUP_SUPPORT )
{
    [string]$logsFolder = $(if( $args.Count -gt 7 ) { $args[ 7 ] } else { $env:CONTROLUP_SUPPORT } )
    $DebugPreference = 'Continue'

    if( $logsFolder -match '^Prep:(\d+)$' )
    {
        [int]$logSize = $Matches[1]
        $securityEventLog = Get-WinEvent -ListLog 'Security'
        [string]$size = $null

        if( $logSize -lt 1 )
        {
            Throw "$logSize cannot be less than 1MB"
        }
        if( $logSize -lt $suggestedSecurityEventLogSizeMB )
        {
            Write-Warning "Log size of $($logSize)MB is less than the recommended $($suggestedSecurityEventLogSizeMB)MB"
        }
        elseif( $logSize -lt $securityEventLog.MaximumSizeInBytes / 1MB )
        {
            Write-Warning "New Security event log size of $($logSize)MB is less than the current $([int]($securityEventLog.MaximumSizeInBytes / 1MB))MB"
        }
        elseif( $logSize -gt $securityEventLog.MaximumSizeInBytes / 1MB )
        {
            Write-Debug "Increasing security event log maximum size to $($logSize)MB from $([int]($securityEventLog.MaximumSizeInBytes / 1MB))MB"
            $size = "/maxsize:$($logSize * 1MB)"
        }
        else
        {
            Write-Warning "Security event log already has max size of $($logSize)MB so not changing"
        }
        
        if( $securityEventLog.LogMode -ne 'Circular' )
        {
            Write-Warning "Security event log was previousy not set to overwrite (was $($securityEventLog.LogMode))"
        }
        
        wevtutil.exe set-log Security /retention:false /autobackup:false $size 
        
        $null = New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -PropertyType 'Dword' -Force
        
        [string[]]$eventLogs = @( 'Microsoft-Windows-PrintService/Operational' , 'Microsoft-Windows-GroupPolicy/Operational' , 'Microsoft-Windows-TaskScheduler/Operational' , 'Microsoft-Windows-User Profile Service/Operational' , 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' )
        [int]$newEventLogSize = 10MB
        ForEach( $eventLog in $eventLogs )
        {
            $eventLogProperties = Get-WinEvent -ListLog $eventLog
            if( $eventLogProperties )
            {
                $commandLine =  "`"$eventLog`" /retention:false /autobackup:false /enabled:true"
                if( $eventLogProperties.MaximumSizeInBytes -ge $newEventLogSize )
                {
                    Write-Warning "Event log `"$eventLog`" already has max size of $([int]($eventLogProperties.MaximumSizeInBytes / 1MB))MB  so not changing"
                }
                else
                {
                    $commandLine += " /maxsize:$newEventLogSize"
                }
                Start-Process -FilePath "wevtutil.exe" -ArgumentList "set-log $commandLine" -Wait -WindowStyle Hidden
            }
        }

        [array]$requiredAuditEvents = @(
            [pscustomobject]@{ 'Policy' = 'Process Creation'     ; 'CategoryGuid' = '6997984C-797A-11D9-BED3-505054503030' ; 'SubCategoryGuid' = '0cce922b-69ae-11d9-bed3-505054503030' }
            [pscustomobject]@{ 'Policy' = 'Process Termination'  ; 'CategoryGuid' = '6997984C-797A-11D9-BED3-505054503030' ; 'SubCategoryGuid' = '0cce922c-69ae-11d9-bed3-505054503030' }
            [pscustomobject]@{ 'Policy' = 'Logon'                ; 'CategoryGuid' = '69979849-797A-11D9-BED3-505054503030' ; 'SubCategoryGuid' = '0cce9215-69ae-11d9-bed3-505054503030' }
        )
        if( ! ( ([System.Management.Automation.PSTypeName]'Win32.Advapi32').Type ) )
        {
            [void](Add-Type -MemberDefinition $AuditDefinitions -Name 'Advapi32' -Namespace 'Win32' -UsingNamespace System.Text,System.ComponentModel,System.Security,System.Security.Principal -Debug:$false)
        }
        [int]$privReturn = [Win32.Advapi32+TokenManipulator]::AddPrivilege( [Win32.Advapi32+Rights]::SeSecurityPrivilege )
        if( $privReturn )
        {
            Write-Warning "Failed to enable SeSecurityPrivilege"
        }
        ForEach( $requiredAuditEvent in $requiredAuditEvents )
        {
            if( ! ( Set-SystemPolicy -categoryGuid $requiredAuditEvent.CategoryGuid -subCategoryGuid $requiredAuditEvent.SubCategoryGuid  ) )
            {
                Write-Warning "Unable to set $($requiredAuditEvent.Policy)"
            }
        }
        Exit 0
    }
    elseif( $logsFolder[0] -eq '+' )
    {
        ## we are dumping the logs
        $logsFolder = $logsFolder.Substring(1)
        if( ! ( Test-Path -Path $logsFolder -PathType Container -ErrorAction SilentlyContinue ) )
        {
            $dumpDir = New-Item -Path $logsFolder -ItemType Directory -Force -ErrorAction Stop
        }
        wevtutil.exe export-log "Application" $(Join-Path -Path $logsFolder -ChildPath 'Application.evtx')
        wevtutil.exe export-log "Security" $(Join-Path -Path $logsFolder -ChildPath 'Security.evtx')
        wevtutil.exe export-log "Microsoft-Windows-GroupPolicy/Operational" $(Join-Path -Path $logsFolder -ChildPath 'Group Policy.evtx')
        wevtutil.exe export-log "Microsoft-Windows-PrintService/Operational" $(Join-Path -Path $logsFolder -ChildPath 'Print Service.evtx')
        wevtutil.exe export-log "Microsoft-Windows-TaskScheduler/Operational" $(Join-Path -Path $logsFolder -ChildPath 'Task Scheduler.evtx')
        wevtutil.exe export-log "Microsoft-Windows-User Profile Service/Operational" $(Join-Path -Path $logsFolder -ChildPath 'User Profile Service.evtx')
        wevtutil.exe export-log "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" $(Join-Path -Path $logsFolder -ChildPath 'Terminal Services LSM.evtx')
        Write-Debug "Required event logs dumped to `"$logsFolder`". Please zip and email to support@controlup.com"
    }
    elseif( Test-Path -Path $logsFolder -PathType Container -ErrorAction SilentlyContinue )
    {
        $offline = $true

        ## look for event log files so we can use instead of live logs
        Get-ChildItem -Path $logsFolder -Filter '*.evtx' -ErrorAction SilentlyContinue | ForEach-Object `
        {
            $file = $_
            switch -Regex( $file.BaseName )
            {
                'sec'         { $global:securityParams = @{ 'Path' = $file.FullName } ; break }
                'group|gpo'   { $global:groupPolicyParams = @{ 'Path' = $file.FullName } ; break }
                'ts|terminal' { $global:terminalServicesParams = @{ 'Path' = $file.FullName } ; break }
                'prof'        { $global:userProfileParams = @{ 'Path' = $file.FullName  } ; break }
                'app'         { $global:citrixUPMParams = @{ 'Path' = $file.FullName } ; break }
                'sched'       { $global:scheduledTasksParams = @{ 'Path' = $file.FullName } ; break }
                'print'       { $global:printServiceParams = @{ 'Path' = $file.FullName } ; break }
            }
        }
        if( ! $global:securityParams[ 'Path' ] )
        {
            Write-Warning "Could not find Security event log file in `"$logsFolder`""
        }
        if( ! $global:groupPolicyParams[ 'Path' ] )
        {
            Write-Warning "Could not find Group Policy operational event log file in `"$logsFolder`""
        }
        if( ! $global:terminalServicesParams[ 'Path' ] )
        {
            Write-Warning "Could not find Terminal Services-Local Session Manager operational event log file in `"$logsFolder`""
        }
        if( ! $global:userProfileParams['Path' ] )
        {
            Write-Warning "Could not find User Profile Service operational event log file in `"$logsFolder`""
        }
        if( ! $global:scheduledTasksParams[ 'Path' ] )
        {
            Write-Warning "Could not find User Task Scheduler operational event log file in `"$logsFolder`""
        }
        if( ! $global:citrixUPMParams[ 'Path' ] )
        {
            Write-Warning "Could not find Application event log (for Citrix Profile Management) file in `"$logsFolder`""
        }
        if( ! $global:printServiceParams[ 'Path' ] )
        {
            Write-Warning "Could not find User Print Service operational event log file in `"$logsFolder`""
        }
        Set-Variable -Name CommandLine -Value 8 -Option ReadOnly -ErrorAction SilentlyContinue
        if( $env:CONTROLUP_OSVERSION )
        {
            $global:windowsMajorVersion = $env:CONTROLUP_OSVERSION
        }
    }
    Write-Debug "Running script as Windows version $global:windowsMajorVersion"
}

if ( $args.Count -ge 7 -and $args[5] -and $args[6]) {
    $XDUsername = $args[5]
    $XDPassword = $args[6]
}

if ($SessionName -eq $null -and $ClientName -eq $null -and $args.count -eq 5) {
    $XDUsername = $args[3]
    $XDPassword = $args[4]
}

if( ! $ClientName -and $args.Count -ge 5 )
{
    $ClientName = $args[4]
}

if( ! $SessionName -and $args.Count -ge 4 )
{
    $SessionName = $args[3]
}

Write-Debug "Logon Parameters discovered:"
Write-Debug "Username:    $Username"
Write-Debug "UserDomain:  $userDomain"
Write-Debug "ClientName:  $ClientName"
Write-Debug "SessionName: $SessionName"
Write-Debug "SessionId:   $SessionID"
Write-Debug "XDUsername:  $XDUserName"

[hashtable]$params = @{
    'Username' = $Username
    'UserDomain' =  $UserDomain
    'ClientName' = $clientName
}
if( $args.Count -ge 2 -and $args[1] )
{
    $params.Add( 'CUDesktopLoadTime' , $args[1] )
}

if ($SessionName -imatch "RDP") {
        Get-LogonDurationAnalysis @params
    }
else {
    $params.Add( 'HDXSessionId' , $SessionId )

    if ($XDUsername -and $XDPassword ) {
        Get-LogonDurationAnalysis @params -XDUsername $XDUsername -XDPassword (ConvertTo-SecureString -String $XDPassword -AsPlainText -Force)
    } else {
        Get-LogonDurationAnalysis @params
    }
}
