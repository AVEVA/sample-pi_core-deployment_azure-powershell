Configuration PIDA
{

    param(
        # Used to run installs. Account must have rights to conduct successful installs/configs
        [parameter(mandatory)]
        [PSCredential]$Credential,
        # PI Data Archive Install settings
        [string]$PIPath,
        [string]$PIProductID,
        [string]$archiveFilesSize = '256',
        [string]$PIHOME = 'F:\Program Files (x86)\PIPC',
        [string]$PIHOME64 = 'F:\Program Files\PIPC',
        [string]$PI_INSTALLDIR = 'F:\PI',
        [string]$PI_EVENTQUEUEDIR = 'F:\PI\queue',
        [string]$PI_ARCHIVEDATDIR = 'G:\PI\arc',
        [string]$PI_FUTUREARCHIVEDATDIR = 'G:\PI\arc\future',
        [string]$PI_ARCHIVESIZE = '256', #in MB

        # Parameters used for PIDA Collective
        [Parameter(Mandatory)]
        [string]$DeployHA,

        [Parameter(Mandatory)]
        [string]$OSIsoftTelemetry,

        [string]$PIDataArchivePrimary,
        [string]$PIDataArchiveSecondary,

        # Create Security groups used for FSTS Mappings
        [boolean]$EnableAdGroupCreation = $true,

        # AD Domain Security Group Names to map to OSIsoft FSTS PI Identities
        [String]$PIAdministratorsADGroup = 'PIAdmins',
        [String]$PIUsersADGroup = 'Domain Users',
        [String]$PIBuffersADGroup = 'PIBuffers',
        [String]$PIInterfacesADGroup = 'PIInterfaces',
        [String]$PIPointsAnalysisCreatorADGroup = 'PIPointsAnalysisCreator',
        [String]$PIWebAppsADGroup = 'PIWebApps',
        [String]$PIConnectorRelaysADGroup = 'PIConnectorRelays',
        [String]$PIDataCollectionManagersADGroup = 'PIDataCollectionManagers',
        [string]$DomainNetBiosName = 'ds',
        [string]$DomainAdminUserName = 'dummy1',
        [String]$DomainAdminPassword = 'dummy2',
        [String]$PrimaryDomainController = 'ds-dc-vm0'

    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xStorage
    Import-DscResource -ModuleName xNetworking
    Import-DscResource -ModuleName xPendingReboot
    Import-DscResource -ModuleName PSDSSupportPIDA
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName PSDSSupportPIVS
    Import-DscResource -ModuleName cChoco


    [System.Management.Automation.PSCredential]$runAsCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$DomainNetBiosName\$($Credential.UserName)", $Credential.Password)

    Node localhost {

        # Necessary if reboots are needed during DSC application/program installations
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }

        #region ### 1. VM PREPARATION ###
        # 1A. Check for new volumes. The uninitialized disk number may vary depending on EC2 type (i.e. temp disk or no temp disk). This logic will test to find the disk number of an uninitialized disk.
        # Elastic Block Storage for Binary Files
        xWaitforDisk Volume_F {
            DiskID           = 2
            retryIntervalSec = 30
            retryCount       = 20
        }
        xDisk Volume_F {
            DiskID      = 2
            DriveLetter = 'F'
            FSFormat    = 'NTFS'
            FSLabel     = 'Apps'
            DependsOn   = '[xWaitforDisk]Volume_F'
        }

        # Elastic Block Storage for Archive Files
        xWaitforDisk Volume_G {
            DiskID           = 3
            retryIntervalSec = 30
            retryCount       = 20
        }
        xDisk Volume_G {
            DiskID      = 3
            DriveLetter = 'G'
            FSFormat    = 'NTFS'
            FSLabel     = 'Archives'
            DependsOn   = '[xWaitforDisk]Volume_G'
        }

        # Elastic Block Storage for Queue Files
        xWaitforDisk Volume_H {
            DiskID           = 4
            retryIntervalSec = 30
            retryCount       = 20
        }
        xDisk Volume_H {
            DiskID      = 4
            DriveLetter = 'H'
            FSFormat    = 'NTFS'
            FSLabel     = 'Events'
            DependsOn   = '[xWaitforDisk]Volume_H'
        }

        # Elastic Block Storage for Backup Files
        xWaitforDisk Volume_I {
            DiskID           = 5
            retryIntervalSec = 30
            retryCount       = 20
        }
        xDisk Volume_I {
            DiskID      = 5
            DriveLetter = 'I'
            FSFormat    = 'NTFS'
            FSLabel     = 'Backups'
            DependsOn   = '[xWaitforDisk]Volume_I'
        }


        # 1B. Create Rule to open PI Net Manager Port
        xFirewall PINetManagerFirewallRule {
            Direction   = 'Inbound'
            Name        = 'PI-System-PI-Net-Manager-TCP-In'
            DisplayName = 'PI System PI Net Manager (TCP-In)'
            Description = 'Inbound rule for PI Data Archive to allow TCP traffic for access to the PI Server'
            Group       = 'PI Systems'
            Enabled     = 'True'
            Action      = 'Allow'
            Protocol    = 'TCP'
            LocalPort   = '5450'
            Ensure      = 'Present'
        }

        # 1C. Enable rules to allow Connection to Secondary when executing the CollectiveManager.ps1 script to form PI Data Archvie Collective.
        # The absence of this rule on the Secondary results in exception thrown during the use of get-WmiObject within CollectiveManager.ps1 script.
        # File Share SMB rule is for allowing archive and data file transer from Primary to Secondary.
        # For increased security, disable after Collective formation..
        xFirewall WindowsManagementInstrumentationDCOMIn {
            Name    = 'WMI-RPCSS-In-TCP'
            Enabled = 'True'
            Action  = 'Allow'
            Ensure  = 'Present'
        }

        xFirewall WindowsManagementInstrumentationWMIIn {
            Name    = 'WMI-WINMGMT-In-TCP'
            Enabled = 'True'
            Action  = 'Allow'
            Ensure  = 'Present'
        }

        xFirewall FileAndPrinterSharingSMBIn {
            Name    = 'FPS-SMB-In-TCP'
            Enabled = 'True'
            Action  = 'Allow'
            Ensure  = 'Present'
        }
        #endregion ### 1. VM PREPARATION ###


        #region ### 2. INSTALL AND SETUP ###


        # 2A. Installing Chocolatey to facilitate package installs.
        
        # Check if install directory is empty, clear it out if not
        Remove-Item C:\Choco\* -Recurse -Force
        cChocoInstaller installChoco {
            InstallDir = "C:\Choco"
        }

        # 2B. Install .NET Framework 4.8
        cChocoPackageInstaller 'dotnetfx' {
            Name      = 'dotnetfx'
            DependsOn = "[cChocoInstaller]installChoco"
        }

        xPendingReboot RebootDotNet {
            Name      = 'RebootDotNet'
            DependsOn = '[cChocoPackageInstaller]dotnetfx'
        }

        #2C. Install PI Data Archive with Client Tools
        Package PISystem {
            Name                 = 'PI Server 2018 Installer'
            Path                 = $PIPath
            ProductId            = $PIProductID
            Arguments            = "/silent ADDLOCAL=PIDataArchive,PITotal,FD_AFExplorer,FD_AFDocs,PiPowerShell,pismt3 PIHOME=""$PIHOME"" PIHOME64=""$PIHOME64"" SENDTELEMETRY=""$OSIsoftTelemetry"" AFACKNOWLEDGEBACKUP=""1"" PI_INSTALLDIR=""$PI_INSTALLDIR"" PI_EVENTQUEUEDIR=""$PI_EVENTQUEUEDIR"" PI_ARCHIVEDATDIR=""$PI_ARCHIVEDATDIR"" PI_FUTUREARCHIVEDATDIR=""$PI_FUTUREARCHIVEDATDIR"" PI_ARCHIVESIZE=""$PI_ARCHIVESIZE"""
            Ensure               = 'Present'
            PsDscRunAsCredential = $runAsCredential # Admin creds due to limitations extracting install under SYSTEM account.
            ReturnCode           = 0, 3010, 1641
            DependsOn            = '[xDisk]Volume_F', '[xDisk]Volume_G', '[xDisk]Volume_H', '[xDisk]Volume_I', '[xPendingReboot]RebootDotNet'
        }

        # 2D. Initiate any outstanding reboots.
        xPendingReboot Reboot1 {
            Name      = 'PostInstall'
            DependsOn = '[Package]PISystem'
        }
        #endregion ### 2. INSTALL AND SETUP ###


        #region ### 3. IMPLEMENT OSISOFT FIELD SERVICE TECHNICAL STANDARDS ###

        #3. i - OPTIONAL - Create Corresponding AD Groups for the Basic Windows Integrated Security Roles. Relevant Service Accounts to map through these groups.
        # Aggregate Security Group parameters in to a single array.

        # Used for PI Data Archive Security setting of AD users and group.
        WindowsFeature ADPS {
            Name   = 'RSAT-AD-PowerShell'
            Ensure = 'Present'
        }


        $PISecurityGroups = @(
            @{Name = $PIBuffersADGroup; Description = 'Identity for PI Buffer Subsystem and PI Buffer Server'; },
            @{Name = $PIInterfacesADGroup; Description = 'Identity for PI Interfaces'; },
            @{Name = $PIUsersADGroup; Description = 'Identity for the Read-only users'; },
            @{Name = $PIPointsAnalysisCreatorADGroup; Description = 'Identity for PIACEService, PIAFService and users that can create and edit PI Points'; }
            @{Name = $PIWebAppsADGroup; Description = 'Identity for PI Vision'; },
            @{Name = $PIConnectorRelaysADGroup; Description = 'Identity for PI Connector Relays'; },
            @{Name = $PIDataCollectionManagersADGroup; Description = 'Identity for PI Data Collection Managers'; }
        )
        # If $EnableAdGroupCreation set to $true, enumerate the PISecurityGroups array and create PI Security Groups in AD.
        if ($EnableAdGroupCreation) {
            ForEach ($Group in $PISecurityGroups) {
                xADGroup "CreatePIAdGroup_$($Group.Name)" {
                    GroupName        = $Group.Name
                    GroupScope       = 'Global'
                    Category         = 'Security'
                    Ensure           = 'Present'
                    Description      = $Group.Description
                    DomainController = $PrimaryDomainController
                    Credential       = $runAsCredential
                    DependsOn        = '[Package]PISystem', '[WindowsFeature]ADPS'
                }
            }

            ## OPTIONAL: To simplify remote access for Quickstart scenario, mapping 'Domain Admins' security group as PIAdmins. (NOT recommended for production.)
            xADGroup AddDomainAdminsToPIAdmins {
                GroupName        = $PIAdministratorsADGroup
                GroupScope       = 'Global'
                Category         = 'Security'
                Ensure           = 'Present'
                Description      = $Group.Description
                DomainController = $PrimaryDomainController
                Credential       = $runAsCredential
                MembersToInclude = 'Domain Admins'
                DependsOn        = '[Package]PISystem', '[WindowsFeature]ADPS'
            }
        }

        # 3A. Create identities for basic WIS roles
        $BasicWISRoles = @(
            @{Name = 'PI Buffers'; Description = 'Identity for PI Buffer Subsystem and PI Buffer Server'; },
            @{Name = 'PI Interfaces'; Description = 'Identity for PI Interfaces'; },
            @{Name = 'PI Users'; Description = 'Identity for the Read-only users'; },
            @{Name = 'PI Points&Analysis Creator'; Description = 'Identity for PIACEService, PIAFService and users that can create and edit PI Points'; }
            @{Name = 'PI Web Apps'; Description = 'Identity for PI Vision'; },
            @{Name = 'PI Connector Relays'; Description = 'Identity for PI Connector Relays'; },
            @{Name = 'PI Data Collection Managers'; Description = 'Identity for PI Data Collection Managers'; }
        )
        Foreach ($BasicWISRole in $BasicWISRoles) {
            PIIdentity "SetBasicWISRole_$($BasicWISRole.Name)" {
                Name               = $BasicWISRole.Name
                Description        = $BasicWISRole.Description
                IsEnabled          = $true
                CanDelete          = $false
                AllowUseInMappings = $true
                AllowUseInTrusts   = $true
                Ensure             = "Present"
                PIDataArchive      = $env:COMPUTERNAME
                DependsOn          = '[Package]PISystem'
            }
        }

        # 3B. i - Remove default identities
        $DefaultPIIdentities = @(
            'PIOperators',
            'PISupervisors',
            'PIEngineers',
            'pidemo'
        )
        Foreach ($DefaultPIIdentity in $DefaultPIIdentities) {
            PIIdentity "DisableDefaultIdentity_$DefaultPIIdentity" {
                Name                 = $DefaultPIIdentity
                Ensure               = "Absent"
                PIDataArchive        = $env:COMPUTERNAME
                DependsOn            = '[Package]PISystem'
                PsDscRunAsCredential = $runAsCredential
            }
        }

        # 3B ii - Disable default identities
        $DefaultPIIdentities = @(
            'PIWorld',
            'piusers'
        )
        Foreach ($DefaultPIIdentity in $DefaultPIIdentities) {
            PIIdentity "DisableDefaultIdentity_$DefaultPIIdentity" {
                Name                 = $DefaultPIIdentity
                IsEnabled            = $false
                AllowUseInTrusts     = $false
                Ensure               = "Present"
                PIDataArchive        = $env:COMPUTERNAME
                DependsOn            = '[Package]PISystem', '[PIIdentity]DisableDefaultIdentity_pidemo' 
                PsDscRunAsCredential = $runAsCredential
            }
        }

        # 3C. Set PI Mappings
        $DesiredMappings = @(
            @{Name = 'BUILTIN\Administrators'; Identity = 'piadmins' }, ## OPTIONAL - Stronger security posture would exclude this mapping. Added here to simplify access for demo purposes.
            @{Name = $($DomainNetBiosName + '\' + $PIAdministratorsADGroup); Identity = 'piadmins' },
            @{Name = $($DomainNetBiosName + '\' + $PIBuffersADGroup); Identity = 'PI Buffers' },
            @{Name = $($DomainNetBiosName + '\' + $PIInterfacesADGroup); Identity = 'PI Interfaces' },
            @{Name = $($DomainNetBiosName + '\' + $PIPointsAnalysisCreatorADGroup); Identity = 'PI Points&Analysis Creator' },
            @{Name = $($DomainNetBiosName + '\' + $PIUsersADGroup); Identity = 'PI Users' },
            @{Name = $($DomainNetBiosName + '\' + $PIWebAppsADGroup); Identity = 'PI Web Apps' },
            @{Name = $($DomainNetBiosName + '\' + $PIConnectorRelaysADGroup); Identity = 'PI Connector Relays' },
            @{Name = $($DomainNetBiosName + '\' + $PIDataCollectionManagersADGroup); Identity = 'PI Data Collection Managers' }
        )
        Foreach ($DesiredMapping in $DesiredMappings) {
            if ($null -ne $DesiredMapping.Name -and '' -ne $DesiredMapping.Name) {
                PIMapping "SetMapping_$($DesiredMapping.Name)" {
                    Name                 = $DesiredMapping.Name
                    PrincipalName        = $DesiredMapping.Name
                    Identity             = $DesiredMapping.Identity
                    Enabled              = $true
                    Ensure               = "Present"
                    PIDataArchive        = $env:COMPUTERNAME
                    DependsOn            = '[Package]PISystem', '[PIIdentity]DisableDefaultIdentity_piusers'
                    PsDscRunAsCredential = $runAsCredential
                }
            }
        }

        # 3D. Set PI Database Security Rules
        $DatabaseSecurityRules = @(
            # PIAFLINK can only be updated if the PIAFLINK service has been configured and running.
            @{Name = 'PIARCADMIN'; Security = 'piadmins: A(r,w)' },
            @{Name = 'PIARCDATA'; Security = 'piadmins: A(r,w)' },
            @{Name = 'PIAUDIT'; Security = 'piadmins: A(r,w)' },
            @{Name = 'PIBACKUP'; Security = 'piadmins: A(r,w)' },
            # PIBACTHLEGACY applies to the old batch subsystem which predates the PI Batch Database.Unless the pibatch service is running, and there is a need to keep it running, this entry can be safely ignored.
            @{Name = 'PIDBSEC'; Security = 'piadmins: A(r,w) | PIWorld: A(r) | PI Data Collection Managers: A(r) | PI Users: A(r) | PI Web Apps: A(r)' },
            @{Name = 'PIDS'; Security = 'piadmins: A(r,w) | PIWorld: A(r) | PI Connector Relays: A(r,w) | PI Data Collection Managers: A(r) | PI Users: A(r) | PI Points&Analysis Creator: A(r,w)' },
            @{Name = 'PIHeadingSets'; Security = 'piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)' },
            @{Name = 'PIMAPPING'; Security = 'piadmins: A(r,w) | PI Web Apps: A(r)' },
            @{Name = 'PIModules'; Security = 'piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)' },
            @{Name = 'PIMSGSS'; Security = 'piadmins: A(r,w) | PIWorld: A(r,w) | PI Users: A(r,w)' },
            @{Name = 'PIPOINT'; Security = 'piadmins: A(r,w) | PIWorld: A(r) | PI Connector Relays: A(r,w) | PI Data Collection Managers: A(r) | PI Users: A(r) | PI Interfaces: A(r) | PI Buffers: A(r,w) | PI Points&Analysis Creator: A(r,w) | PI Web Apps: A(r)' },
            @{Name = 'PIReplication'; Security = 'piadmins: A(r,w) | PI Data Collection Managers: A(r)' },
            @{Name = 'PITRUST'; Security = 'piadmins: A(r,w)' },
            @{Name = 'PITUNING'; Security = 'piadmins: A(r,w)' },
            @{Name = 'PIUSER'; Security = 'piadmins: A(r,w) | PIWorld: A(r) | PI Connector Relays: A(r) | PI Data Collection Managers: A(r) | PI Users: A(r) | PI Web Apps: A(r)' }

            #@{Name = 'PIBatch'; Security = 'piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'},
            #@{Name = 'PIAFLINK';            Security = 'piadmins: A(r,w)'},
            #@{Name = 'PIBATCHLEGACY';       Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'},
            #@{Name = 'PICampaign'; Security = 'piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'},
            #@{Name = 'PITransferRecords'; Security = 'piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'}
        )
        Foreach ($DatabaseSecurityRule in $DatabaseSecurityRules) {
            PIDatabaseSecurity "SetDatabaseSecurity_$($DatabaseSecurityRule.Name)" {
                Name          = $DatabaseSecurityRule.Name
                Security      = $DatabaseSecurityRule.Security
                Ensure        = "Present"
                PIDataArchive = $env:COMPUTERNAME
                DependsOn     = '[Package]PISystem'
            }
        }

        # 3F. Restrict use of the piadmin superuser. IMPORTANT NOTE - This change must occur last. Initial connection is via loop back trust. This gets disabled when this change occurs.
        PIIdentity Restrict_piadmin {
            Name                 = "piadmin"
            AllowUseInTrusts     = $true  ## NOTE - This is so local services can still operate. This is used by the loopback trust.
            AllowUseInMappings   = $false
            Ensure               = "Present"
            PIDataArchive        = $env:COMPUTERNAME
            PsDscRunAsCredential = $runAsCredential
            DependsOn            = '[Package]PISystem'
        }
        #endregion ### 3. IMPLEMENT OSISOFT FIELD SERVICE TECHNICAL STANDARDS ###


        #region ### 4. BACKUP CONFIGURATION ###
        # 4-A. Setup PI Server local backup scheduled task.
        Script PIBackupTask {
            GetScript            = {
                $task = (Get-ScheduledTask).TaskName | Where-Object { $_ -eq 'PI Server Backup' }
                Result = "$task"
            }

            TestScript           = {
                $task = (Get-ScheduledTask).TaskName | Where-Object { $_ -eq 'PI Server Backup' }
                if ($task) {
                    Write-Verbose -Message "'PI Server Backup' scheduled task already present. Skipping task install."
                    return $true
                }
                else {
                    Write-Verbose -Message "'PI Server Backup' scheduled task not found."
                    return $false
                }
            }

            SetScript            = {
                Write-Verbose -Message "Creating 'PI Server Backup' scheduled task. Check C:\PIBackupTaskErrors.txt and C:\PIBackupTaskOutput.txt for details."
                $result = Start-Process -NoNewWindow -FilePath "$env:PISERVER\adm\pibackuptask.bat" -WorkingDirectory "$env:PISERVER\adm"  -ArgumentList "I:\PIBackups -install" -Wait -PassThru -RedirectStandardError 'C:\PIBackupTaskErrors.txt' -RedirectStandardOutput 'C:\PIBackupTaskOutput.txt'
                $exitCode = $result.ExitCode.ToString()
                Write-Verbose -Message "Exit code: $exitCode"
            }

            PsDscRunAsCredential = $runAsCredential
            DependsOn            = '[Package]PISystem'
        }


        #endregion ### 4. BACKUP CONFIGURATION ###


        #region ### 5. CREATE PI DATA ARCHIVE COLLECTIVE ###
        if (($DeployHA -eq 'true') -and ($env:COMPUTERNAME -eq $PIDataArchivePrimary)) {
            xWaitForPIServer WaitingForSecondaryServer {
                Name                 = $PIDataArchiveSecondary
                PsDscRunAsCredential = $runAsCredential
            }
            xPIDACollective FormCollective {
                PICollectiveName        = $PIDataArchivePrimary
                PIPrimaryName           = $PIDataArchivePrimary
                PISecondaryNames        = $PIDataArchiveSecondary
                BackupLocationOnPrimary = "I:\PIBackups"
                Credential              = $runAsCredential

            }
        }

        

        #region 6. Deployment Test Firewall Rules
        xFirewall RSMForTestsEPMAP {
            Group = 'Remote Service Management'
            Name    = 'Remote Service Management (RPC-EPMAP)'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        xFirewall RSMForTestsRPC {
            Group = 'Remote Service Management'
            Name    = 'Remote Service Management (RPC)'
            Ensure  = 'Present'
            Enabled = 'True'
        }
        xFirewall RSMForTestsNP {
            Group = 'Remote Service Management'
            Name    = 'Remote Service Management (NP-In)'
            Ensure  = 'Present'
            Enabled = 'True'
        }

        xFirewall PingForTests {
            Name    = 'FPS-ICMP4-ERQ-In'
            Ensure  = 'Present'
            Enabled = 'True'
        }   
        #endregion
    }
}

# SIG # Begin signature block
# MIIpTQYJKoZIhvcNAQcCoIIpPjCCKToCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD2fp2t+7/rc6Wt
# LAF0v76fvnNFBduPU/LFzL+3lEsfu6CCDhkwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggdhMIIFSaADAgECAhAPU7nOpIHX2AURH287XM6zMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjIwNzEzMDAwMDAwWhcNMjMwODAy
# MjM1OTU5WjBmMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIG
# A1UEBxMLU2FuIExlYW5kcm8xFTATBgNVBAoTDE9TSXNvZnQsIExMQzEVMBMGA1UE
# AxMMT1NJc29mdCwgTExDMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# vvUpI/RMd0etxSSqHSbhyPm/7pRPL/f0i/x2olGznPFkzv/r0eI/ANvtWI8GSRuU
# U6HL/tExJrd3BYZNM+y78mZScEBACLWAsP6PrREOXPEb4WryIddu7PLVBlmkXRvO
# BFeiIkm/cQMZ5/2zBa3JM5Ox+W7wWxOqvU6TrHtWaG+E3bOppi5XnS3VC0IRfWDn
# gSzaSCIR8M7PQo9dnVclneqbjunk24Nc4nNgMsNclThLiX+8MlE2GwFw0z3aheQk
# wC9MuWuOrFeLbd8u45qJmXnGPFjsrB8T+1G8cs5A66f7jxW1/8A8L1hYlJ67D01u
# ySCao5nHXLyrGBScEvc0HLPHY2esOf9ZSKK76U52EcFkv8rexaxjiOeUqL1tTofy
# 0rmXvfjz7fVUB2XnLTKjbrf7CdwzK07ZifOlwvUhCDcoe5HatsuKBc4js695oGDm
# 7oeorEbDoEsn0JxEA+ZcmW7YE1/z1QCeua1caaj4WLUZdD/NctcYRXRC64WHOCnI
# 0mtxtIRAtnXdJkMG1v7T1OTrSQdpJa/DBhYfSnVMbQ0HBdwdPj5+7M/4vuNRY5PG
# 2s6sc/fNdOEcTwZpqd4oIgchwKXlz/D6l5Y/REOJvR7NtqiyCuGQPf0NoUkJB78M
# Cdi8JmM4FrUXJaPTWWqZFdHhi/1fvt+fzTnrMQ1Id/kCAwEAAaOCAgYwggICMB8G
# A1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBS0iFWmypnR
# uL0Z6XGSDXm8oY6WujAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNB
# MS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMD4GA1Ud
# IAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNl
# cnQuY29tL0NQUzCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2
# U0hBMzg0MjAyMUNBMS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOC
# AgEAvG+uJmPKqu+YBqcbyR2BmGDSiiU+510qD7BlxTpA7LgvQOEfszG2LPhk8uoI
# /QTm2SR+EKm21HYfoJd50wDNSVk1gDhYBi78HTk8e0TuhgcC+C6nQlygGXLYNuQu
# sfyEofV99OZcjrzJ3bl2th2EkCQHD6BBCuZlsXZlOF1HYXeyNf+FLzqC1E8BtV+k
# fCMi8cbwLpr+ZitY6wrE5Rnnd5jWhu9af1mm8UWcnt9yef67N6bCrNZFjy3zf5bS
# Vo7yIZb88Tsw2xbqAnWkBDvFhaCsEqXktbjQQydRIGrImpY7URvvXNSN8/V+bp1/
# PJwOOm4iq/d+jjrFJxpNIgDGjXx5YU9DtJk7o6zmVO0KidfHb578YxL3Ugj+I9ds
# oykeKKsnb/4EdnvHKyzv45bpZ3HI96q7+rx0N5Q9HDBR6XVTopJFB01t00nKyxTB
# 3Kq8TX5Qb+8omlrG3XEou6QqsmizfecHcpHxQh2hNtnamfAj253+joKES3kQWch/
# 9lDET0f5+ZvB7eERRhOFQcazv/J4Bl4yvPfPcJVeq0q12lkulHiOGACu1JoCDAIB
# YyqAuh1xmfV/za/aVYnh2GkbHqTEH4U+jkkyTzo/lftxzh8zkOwZGmK8hG2oLlKk
# 3gbIhtAHY4vZjeP6cJwRNpxg12nbe25nQ6vuvIsuJ6eS59QxghqKMIIahgIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA9Tuc6kgdfYBREfbztczrMwDQYJYIZIAWUDBAIBBQCggZ4w
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJvHRKNDOO38p7TYSMSZWZgRFJEbEIR0
# B9GWqHpCIKR0MDIGCisGAQQBgjcCAQwxJDAioSCAHmh0dHA6Ly90ZWNoc3VwcG9y
# dC5vc2lzb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAgAz0m9BCBt56lJY4Rii2v+d
# qRlY1tIwHo8ngXULnlCRmkM1Aa2d6pHA9n7flCMKwAo4sqw3slJDr9D6kEwBKevD
# dwLsS3DLiFWr77to1q9k0M8pDJMXz+gTE6D5EAgrLO6+WoO4YQv1C2mRvwtKQLtk
# 3O7+D44newwsWOts/7TOxz8MFzmNnxEr7QLhMJuIbkq+8eF7pBlTYQKVmA9dNu5h
# WbLhUnbJX28AlD0WtZF6ZZU4m2kkDFMKilAwzD044O40IQm2eAaCMsCFWbujXjZR
# G+pugei+IV56fFw1kOfZ32L0T19hscf8iDL8Jj1KljScsbNIsM0iHfIwlxOUHq7W
# yUwlH8aa7YdNLXYCSlqnAKTkE+Pt8AogywmyjEXoTVRFO0aDUdTo+XE45J2KrC78
# ri5kiL3MRx58p8AkhNPtcm0G0zXliTFKK+AdUg/F4jFy5+q29srb3hOOChrbqYll
# hZraV3hpDalaTka3s00AdZ+ckh8nqhbcSJjNzSX4n2fCO35/ZD0UwwlvZsQcX3rd
# OC3KBThplAA1nQkRSQJSvL+aXjDHdFtKrhNU2vIjhM3WmNtpNifXYueV6dqNQQpV
# ItVsDtvRmFQf/RLR7F9Khsh3aYbfCzXXDUYF3qEWnkQFha9MlVup/PhuPQUoo/gs
# qQCkNzWFgASl5kiFBfWv4qGCFz0wghc5BgorBgEEAYI3AwMBMYIXKTCCFyUGCSqG
# SIb3DQEHAqCCFxYwghcSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQ
# AQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCC7kliKUXSI
# Ai/sOghdJFy+3o7+uclGlRBkMM3TlphVwAIQGb1Vm/NzGs5WhNiuoDxmlhgPMjAy
# MjEwMjExODIxMDFaoIITBzCCBsAwggSooAMCAQICEAxNaXJLlPo8Kko9KQeAPVow
# DQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hB
# MjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMjA5MjEwMDAwMDBaFw0zMzExMjEyMzU5
# NTlaMEYxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2VydDEkMCIGA1UEAxMb
# RGlnaUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAz+ylJjrGqfJru43BDZrboegUhXQzGias0BxVHh42bbySVQxh
# 9J0Jdz0Vlggva2Sk/QaDFteRkjgcMQKW+3KxlzpVrzPsYYrppijbkGNcvYlT4Dot
# jIdCriak5Lt4eLl6FuFWxsC6ZFO7KhbnUEi7iGkMiMbxvuAvfTuxylONQIMe58ty
# SSgeTIAehVbnhe3yYbyqOgd99qtu5Wbd4lz1L+2N1E2VhGjjgMtqedHSEJFGKes+
# JvK0jM1MuWbIu6pQOA3ljJRdGVq/9XtAbm8WqJqclUeGhXk+DF5mjBoKJL6cqtKc
# tvdPbnjEKD+jHA9QBje6CNk1prUe2nhYHTno+EyREJZ+TeHdwq2lfvgtGx/sK0YY
# oxn2Off1wU9xLokDEaJLu5i/+k/kezbvBkTkVf826uV8MefzwlLE5hZ7Wn6lJXPb
# wGqZIS1j5Vn1TS+QHye30qsU5Thmh1EIa/tTQznQZPpWz+D0CuYUbWR4u5j9lMNz
# IfMvwi4g14Gs0/EH1OG92V1LbjGUKYvmQaRllMBY5eUuKZCmt2Fk+tkgbBhRYLqm
# gQ8JJVPxvzvpqwcOagc5YhnJ1oV/E9mNec9ixezhe7nMZxMHmsF47caIyLBuMnnH
# C1mDjcbu9Sx8e47LZInxscS451NeX1XSfRkpWQNO+l3qRXMchH7XzuLUOncCAwEA
# AaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB
# /wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUYore
# 0GH8jzEU7ZcLzT0qlBTfUpwwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVT
# dGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRp
# bWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAVaoqGvNG83hXNzD8
# deNP1oUj8fz5lTmbJeb3coqYw3fUZPwV+zbCSVEseIhjVQlGOQD8adTKmyn7oz/A
# yQCbEx2wmIncePLNfIXNU52vYuJhZqMUKkWHSphCK1D8G7WeCDAJ+uQt1wmJefkJ
# 5ojOfRu4aqKbwVNgCeijuJ3XrR8cuOyYQfD2DoD75P/fnRCn6wC6X0qPGjpStOq/
# CUkVNTZZmg9U0rIbf35eCa12VIp0bcrSBWcrduv/mLImlTgZiEQU5QpZomvnIj5E
# IdI/HMCb7XxIstiSDJFPPGaUr10CU+ue4p7k0x+GAWScAMLpWnR1DT3heYi/HAGX
# yRkjgNc2Wl+WFrFjDMZGQDvOXTXUWT5Dmhiuw8nLw/ubE19qtcfg8wXDWd8nYive
# QclTuf80EGf2JjKYe/5cQpSBlIKdrAqLxksVStOYkEVgM4DgI974A6T2RUflzrgD
# QkfoQTZxd639ouiXdE4u2h4djFrIHprVwvDGIqhPm73YHJpRxC+a9l+nJ5e6li6F
# V8Bg53hWf2rvwpWaSxECyIKcyRoFfLpxtU56mWz06J7UWpjIn7+NuxhcQ/XQKuji
# Yu54BNu90ftbCqhwfvCXhHjjCANdRyxjqCU4lwHSPzra5eX25pvcfizM/xdMTQCi
# 2NYBDriL7ubgclWJLCcZYfZ3AYwwggauMIIElqADAgECAhAHNje3JFR82Ees/Shm
# Kl5bMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERp
# Z2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIy
# MzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7
# MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1l
# U3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUG
# SbPBPXJJUVXHJQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOc
# iQt/nR+eDzMfUBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkr
# PkLcZ47qUT3w1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rw
# N3mfXazL6IRktFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSm
# xR3NNg1c1eYbqMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu
# 9Yemj052FVUmcJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirH
# kr+g3uM+onP65x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506
# o9UD4L/wojzKQtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklN
# iyDSLFc1eSuo80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGT
# yYwMO1uKIqjBJgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgA
# DoRU7s7pXcheMBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYD
# VR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNV
# HR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwDQYJKoZIhvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPP
# MFPOvxj7x1Bd4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKW
# b8RQTGIdDAiCqBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpP
# kWaeLJ7giqzl/Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXa
# zPByoyP6wCeCRK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKv
# xMfBwWpx2cYTgAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl6
# 3f8lY5knLD0/a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YB
# T70/O3itTK37xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4n
# LCbbbxV7HhmLNriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvt
# lUG3OtUVmDG0YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm
# 2fBldkKmKYcJRyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqh
# K/bt1nz8MIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMYIDdjCCA3IC
# AQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5
# BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0
# YW1waW5nIENBAhAMTWlyS5T6PCpKPSkHgD1aMA0GCWCGSAFlAwQCAQUAoIHRMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjIxMDIx
# MTgyMTAxWjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBTzhyJNhjOCkjWplLy9j5bp
# /hx8czAvBgkqhkiG9w0BCQQxIgQgkApYCaBaJYGQKZ+BM/L9a4JD4xsOn9nsCw6A
# ViqcKM0wNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgx/ThvjIoiSCr4iY6vhrE/E/m
# eBwtZNBMgHVXoCO1tvowDQYJKoZIhvcNAQEBBQAEggIACkvYTG+RIi4frZjb1tK3
# 9ou2sCHpQBkWiEdvhYIfXR1XrLcscC6/+Cc0Z3A1KxtMJmbpNXKlVIqTaUmgiYid
# VCr8koB4J9JAyDTQdZ6yJXNwMnkkHMyYi91XmhUiShPnaIcRzegUylqzDHMxjeNb
# kr8/e6P3/mOLN8UV4EGL/7rrkaNH8s0sPc1cuLkj4o2KuAmJ9bmrSdfQWEx1UL0O
# yxTt3+wRVmJFjz2Y5AVYNc93VFQOBVWYW2guB8zScwyVzK3dNAyxPGfvpdOF2WLY
# F5WiezORATrOwxRMHFCLWuzcC3TZsKWV5WyVk/ZyTrx2Nxy3bwTJarpv2pi5OhUX
# Y+8czXwq0Y0ytiSJq16VrVoPW5NOuD2IHg2PN+eDHWDVgD/JQA3+aAKiZg4xtm9h
# C2Vwa60rlUrweO2kKoKrN+eJlC8yzBtOnUJ3IdL954We0HBksZo7neYoDsxbH2lR
# qSraz4bIEyegUkg+DWWiHtHIY1i0CcdWnoVkkI9mUqTIkUIOtIEglzIxY4MU+l/5
# o71oRNHFJvSW1+XY/YgHoPAwCGi4wCJBC40UF3f6i0Z8d0yAw0Y8ECYU1I/D11Or
# dlnPZYPxcUx+e+7Xec3cgGyOzUuEsATY1ppwQCWfFOv5edliZ1HUjN1fjA+azfPu
# jco2Nz8OgCSv9jJKyE7qnBU=
# SIG # End signature block
