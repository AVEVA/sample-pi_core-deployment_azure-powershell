Configuration PIVS
{
    param(
        [string]$PIVisionPath = 'D:\PI Vision_2019 Patch 1_.exe',
        # Used to run installs. Account must have rights to AD and SQL to conduct successful installs/configs.
        [Parameter(Mandatory)]
        [pscredential]$runAsCredential,
        # Service account used to run PI Vision and PI Web API.
        [pscredential]$svcCredential,
        # AD group mapped to correct privileges on the PI Data Archive, need to add above svc acct to this
        [String]$PIWebAppsADGroup = 'PIWebApps',

        # PI AF Server Install settings
        [string]$PIHOME = 'F:\Program Files (x86)\PIPC',
        [string]$PIHOME64 = 'F:\Program Files\PIPC',
        [string]$VisionDBName = "PIVisionDB",

        # Switch to indicate highly available deployment
        [string]$namePrefix,
        [string]$nameSuffix,

        # Primary domain controller for AD Group manipulation
        [String]$PrimaryDomainController = ($namePrefix + '-dc-vm' + $nameSuffix),

        # SQL Server to install PI Vision database. This should be the primary SQL server hostname.
        [string]$DefaultSqlServer = ($namePrefix + '-sql-vm' + $nameSuffix),
        [string]$SQLSecondary = ($namePrefix + '-sql-vm1'),

        [string]$DefaultPIAFServer = ($namePrefix + '-piaf-vm' + $nameSuffix),

        [string]$DefaultPIDataArchive = ($namePrefix + '-pida-vm' + $nameSuffix),

        [string]$sqlAlwaysOnAvailabilityGroupName = ($namePrefix + '-sqlag' + $nameSuffix),

        # Name used to identify VS load balanced endpoint for HA deployments. Used to create DNS CName record.
        [string]$VSLoadBalancedName = 'PIVS',
        [string]$VSLoadBalancerIP,

        # PI Vision server names
        [string]$VSPrimary,
        [string]$VSSecondary,

        # SQL Server Always On Listener.
        [string]$SqlServerAOListener = 'AG0-Listener',
    
        # Switch to indicate highly available deployment
        [Parameter(Mandatory)]
        [string]$deployHA
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName cChoco
    Import-DscResource -ModuleName PSDSSupportPIVS
    Import-DscResource -ModuleName xWebAdministration
    Import-DscResource -ModuleName xNetworking
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xPendingReboot
    Import-DscResource -ModuleName xStorage
    Import-DscResource -ModuleName xDnsServer
    Import-DscResource -ModuleName SqlServerDsc

    Import-Module -Name SqlServer

    # Under HA deployment senarios, subsitute the primary SQL Server hostname for the SQL Always On Listner Name.
    # This is used in the installation arguements for PI Vision. This value get's cofigured in the PIVision\Admin specifying which SQL intance to connect to.
    if ($deployHA -eq "true") {
        Write-Verbose -Message "HA deployment detected. PI Vision install will use the following SQL target: $SqlServerAOListener" -Verbose
        $FDSQLDBSERVER = $SqlServerAOListener

        Write-Verbose -Message "HA deployment detected. PI AF Server will point to AF load balanced name 'PIAF'." -Verbose
        Write-Verbose -Message "'PIAF' is an internal DNS CName record pointing to the AWS internal load balancer for AF. See PIAF deployment." -Verbose
        $DefaultPIAFServer = 'PIAF'

    }
    else {
        Write-Verbose -Message "Single instance deployment detected. PI Vision install will use the following SQL target: $DefaultSqlServer" -Verbose
        $FDSQLDBSERVER = $DefaultSqlServer
    }

    # Lookup Domain names (FQDN and NetBios). Assumes VM is already domain joined.
    $DomainNetBiosName = ((Get-WmiObject -Class Win32_NTDomain -Filter "DnsForestName = '$((Get-WmiObject -Class Win32_ComputerSystem).Domain)'").DomainName)
    $DomainDNSName = (Get-WmiObject Win32_ComputerSystem).Domain

    # Extracts username only (no domain net bios name) for domain runas account
    $runAsAccountUsername = $runAsCredential.UserName
    # Create credential with Domain Net Bios Name included.
    $domainRunAsCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ("$DomainNetBiosName\$runAsAccountUsername", $runAsCredential.Password)

    # Extracts username only (no domain net bios name)
    $PIVSSvcAccountUsername = $svcCredential.UserName
    # Create credential with Domain Net Bios Name included.
    $domainSvcCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ("$DomainNetBiosName\$PIVSSvcAccountUsername", $svcCredential.Password)

    # Agreggate parameters used for PI Vision configuration settings
    [string]$allowedDAServers = $DefaultPIDataArchive
    [string]$visionScriptPath = "$PIHOME64\PIVision\Admin\SQL"
    [string]$svcRunAsDomainAccount = $PIVSSvcAccountUsername

    Node localhost {

        # Necessary if reboots are needed during DSC application/program installations
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }

        #region ### 1. VM PREPARATION ###
        # 1A. Check for new volumes. The uninitialized disk number may vary depending on EC2 type (i.e. temp disk or no temp disk). This logic will test to find the disk number of an uninitialized disk.
        $disks = Get-Disk | Where-Object 'partitionstyle' -eq 'raw' | Sort-Object number
        if ($disks) {
            # Elastic Block Storage for Binary Files
            xWaitforDisk Volume_F {
                DiskID           = $disks[0].number
                retryIntervalSec = 30
                retryCount       = 20
            }
            xDisk Volume_F {
                DiskID      = $disks[0].number
                DriveLetter = 'F'
                FSFormat    = 'NTFS'
                FSLabel     = 'Apps'
                DependsOn   = '[xWaitforDisk]Volume_F'
            }
        }

        # 1B i.Open firewall rules for PI Vision
        xFirewall PIVSHttpFirewallRule {
            Direction   = 'Inbound'
            Name        = 'PI-System-PI-Vision-HTTP-TCP-In'
            DisplayName = 'PI System PI Vision HTTP (TCP-In)'
            Description = 'Inbound rule for PI Vision to allow HTTP traffic.'
            Group       = 'PI Systems'
            Enabled     = 'True'
            Action      = 'Allow'
            Protocol    = 'TCP'
            LocalPort   = '80'
            Ensure      = 'Present'
        }

        # 1B ii. Open firewall rules for PI Vision
        xFirewall PIVSHttpsFirewallRule {
            Direction   = 'Inbound'
            Name        = 'PI-System-PI-Vision-HTTPS-TCP-In'
            DisplayName = 'PI System PI Vision HTTPS (TCP-In)'
            Description = 'Inbound rule for PI Vision to allow HTTPS traffic.'
            Group       = 'PI Systems'
            Enabled     = 'True'
            Action      = 'Allow'
            Protocol    = 'TCP'
            LocalPort   = '443'
            Ensure      = 'Present'
        }
        #endregion ### 1. VM PREPARATION ###


        #region ### 2. INSTALL AND SETUP ###
        # 2A i. Used for PI Vision Service account creation.
        WindowsFeature ADPS {
            Name   = 'RSAT-AD-PowerShell'
            Ensure = 'Present'
        }

        # 2B i. Install IIS Web Server Features
        WindowsFeature IIS {
            Ensure = "Present"
            Name   = "Web-Server"
        }

        # 2B ii. Install IIS Tools
        WindowsFeature IISManagementTools {
            Ensure    = "Present"
            Name      = "Web-Mgmt-Tools"
            DependsOn = '[WindowsFeature]IIS'
        }

        # 2C i. Installing Chocolatey to facilitate package installs.

        # Check if install directory is empty, clear it out if not
        Remove-Item C:\Choco\* -Recurse -Force
        cChocoInstaller installChoco {
            InstallDir = "C:\Choco"
        }

        # 2C ii. Need 7zip to exact files from PI Vision executable for installation.
        cChocoPackageInstaller '7zip' {
            Name      = '7zip'
            DependsOn = "[cChocoInstaller]installChoco"
        }

        # 2D i. Install .NET Framework 4.8.
        cChocoPackageInstaller 'dotnetfx' {
            Name      = 'netfx-4.8-devpack'
            Ensure    = 'Present'
            Version   = '4.8.0.20190930'
            DependsOn = '[cChocoInstaller]installChoco'
        }

        # 2D ii. Reboot to complete .NET installation.
        xPendingReboot RebootDotNet {
            Name      = 'RebootDotNet'
            DependsOn = '[cChocoPackageInstaller]dotnetfx'
        }

        # If a load balancer DNS record is passed, then this will generate a DNS CName. This entry is used as the PIVS load balanced endpoint.
        if ($deployHA -eq 'true') {
            # Tools needed to write DNS Records
            WindowsFeature DNSTools {
                Name   = 'RSAT-DNS-Server'
                Ensure = 'Present'
            }

            # Adds a AName DNS record used to point to internal Elastic Load Balancer DNS record
            xDnsRecord VSLoadBanacedEndPoint {
                Name                 = $VSLoadBalancedName
                Target               = $VSLoadBalancerIP
                Type                 = 'ARecord'
                Zone                 = $DomainDNSName
                DnsServer            = $PrimaryDomainController
                DependsOn            = '[WindowsFeature]DnsTools'
                Ensure               = 'Present'
                PsDscRunAsCredential = $runAsCredential
            }
        }

        # 2E i. Custom DSC resource to install PI Vision.
        # This resource helps update silent installation files to facilitate unattended install.
        xPIVisionInstall 'InstallPIVision' {
            InstallKitPath       = $PIVisionPath
            AFServer             = $DefaultPIAFServer
            PIServer             = $DefaultPIDataArchive
            ConfigInstance       = $env:COMPUTERNAME
            ConfigAssetServer    = $DefaultPIAFServer
            PIHOME               = $PIHOME
            PIHOME64             = $PIHOME64
            Ensure               = 'Present'
            PSDscRunAsCredential = $domainRunAsCredential
            DependsOn            = '[xPendingReboot]RebootDotNet'
        }

        # 2F i. Required to execute PI Vision SQL database install
        cChocoPackageInstaller 'sqlserver-odbcdriver' {
            Name      = 'sqlserver-odbcdriver'
            DependsOn = "[cChocoInstaller]installChoco"
        }

        # 2F ii. Required to execute PI Vision SQL database install. Requires reboot to be functional.
        cChocoPackageInstaller 'sqlserver-cmdlineutils' {
            Name      = 'sqlserver-cmdlineutils'
            DependsOn = "[cChocoInstaller]installChoco"
        }

        # 2G ii. Configure HTTP SPN on service account instead and setup Kerberos delegation.
        # We need to do this before modifications that will require this setup, specifically updating PI Web API Cralwer targets.
        xADServicePrincipalName 'SPN01'
        {
            ServicePrincipalName = $("HTTP/" + $env:COMPUTERNAME + ":5985" )
            Account              = $($env:COMPUTERNAME + "$")
            PsDscRunAsCredential = $domainRunAsCredential
            DependsOn            = '[WindowsFeature]ADPS'
        }
        xADServicePrincipalName 'SPN02'
        {
            ServicePrincipalName = $("HTTP/" + $env:COMPUTERNAME + "." + $DomainDNSName + ":5985" )
            Account              = $($env:COMPUTERNAME + "$")
            PsDscRunAsCredential = $domainRunAsCredential
            DependsOn            = '[WindowsFeature]ADPS'
        }

        xADServicePrincipalName 'SPN03'
        {
            ServicePrincipalName = $("HTTP/" + $env:COMPUTERNAME + ":5986" )
            Account              = $($env:COMPUTERNAME + "$")
            PsDscRunAsCredential = $domainRunAsCredential
            DependsOn            = '[WindowsFeature]ADPS'
        }
        xADServicePrincipalName 'SPN04'
        {
            ServicePrincipalName = $("HTTP/" + $env:COMPUTERNAME + "." + $DomainDNSName + ":5986" )
            Account              = $($env:COMPUTERNAME + "$")
            PsDscRunAsCredential = $domainRunAsCredential
            DependsOn            = '[WindowsFeature]ADPS'
        }

        xADServicePrincipalName 'SPN05'
        {
            ServicePrincipalName = $("HTTP/" + $env:COMPUTERNAME)
            Account              = $PIVSSvcAccountUserName
            PsDscRunAsCredential = $domainRunAsCredential
            DependsOn            = '[WindowsFeature]ADPS'
        }
        xADServicePrincipalName 'SPN06'
        {
            ServicePrincipalName = $("HTTP/" + $env:COMPUTERNAME + "." + $DomainDNSName)
            Account              = $PIVSSvcAccountUserName
            PsDscRunAsCredential = $domainRunAsCredential
            DependsOn            = '[WindowsFeature]ADPS'
        }

        if ($deployHA -eq 'true' -and $env:COMPUTERNAME -eq $VSPrimary) {
            xADServicePrincipalName 'SPN07'
            {
                ServicePrincipalName = $("HTTP/" + $VSLoadBalancedName)
                Account              = $PIVSSvcAccountUserName
                PsDscRunAsCredential = $domainRunAsCredential
                DependsOn            = '[WindowsFeature]ADPS'
            }
            xADServicePrincipalName 'SPN08'
            {
                ServicePrincipalName = $("HTTP/" + $VSLoadBalancedName + "." + $DomainDNSName)
                Account              = $PIVSSvcAccountUserName
                PsDscRunAsCredential = $domainRunAsCredential
                DependsOn            = '[WindowsFeature]ADPS'
            }
        }

        Script ConfigSPN {
            # Must return a hashtable with at least one key named 'Result' of type String
            GetScript            = {
                return @{
                    Value = 'ConfigSPN'
                }
            }

            # Must return a boolean: $true or $false
            TestScript           = {
                $File = 'C:\ConfigSPNExecuted.txt'
                $Content = 'ConfigSPN Executed'
 
                If ((Test-path $File) -and (Select-String -Path $File -SimpleMatch $Content -Quiet)) {
                    $True
                }
                Else {
                    $False
                }
            }

            # Returns nothing. Configures Kerberos delegation
            SetScript            = {
                $VerbosePreference = $Using:VerbosePreference

                'ConfigSPN Executed' | Out-File C:\ConfigSPNExecuted.txt

                # THE KERB DELEGATION DID NOT GET IMPLEMENTED
                Write-Verbose -Message "2. Setting Kerberos Constrained Delegation on ""$using:svcRunAsDomainAccount"" for AF Server ""$($using:DefaultPIAFServer)"", PI Data Archive ""$($using:DefaultPIDataArchive)"", and SQL Server instance ""$($using:DefaultSqlServer)""."

                # THE BELOW DELEGATIONS ALSO DID NOT GET CREATED
                $delgationAf = 'AFSERVER/' + "$using:DefaultPIAFServer"
                $delgationAfFqdn = 'AFSERVER/' + $using:DefaultPIAFServer + '.' + $using:DomainDNSName
                $delgationPi = 'PISERVER/' + $using:DefaultPIDataArchive
                $delgationPiFqdn = 'PISERVER/' + $using:DefaultPIDataArchive + '.' + $using:DomainDNSName
                $delgationSqlFqdn = 'MSSQLSvc/' + $using:DefaultSqlServer + '.' + $using:DomainDNSName
                $delgationSqlFqdnPort = 'MSSQLSvc/' + $using:DefaultSqlServer + '.' + $using:DomainDNSName + ':1433'

                Set-ADUser -Identity $using:PIVSSvcAccountUserName -add @{'msDS-AllowedToDelegateTo' = $delgationAf, $delgationAfFqdn, $delgationPi, $delgationPiFqdn, $delgationSqlFqdn, $delgationSqlFqdnPort } -Verbose

                # Note that -TrustedToAuthForDelegation == "Use any authentication protocol" and -TrustedForDelegation == "Use Kerberos Only".
                Write-Verbose -Message "3. Setting delegation to 'Use any authentication protocol'."
                Set-ADAccountControl -TrustedToAuthForDelegation $true -Identity $using:PIVSSvcAccountUserName -Verbose
            }

            # Script must execute under an domain creds with permissions to add/remove SPNs.
            PsDscRunAsCredential = $domainRunAsCredential
            DependsOn            = '[WindowsFeature]ADPS'
        }

        # 2H. Trips any outstanding reboots due to installations.
        xPendingReboot 'Reboot1' {
            Name      = 'PostInstall'
            DependsOn = '[xPIVisionInstall]InstallPIVision', '[cChocoPackageInstaller]sqlserver-cmdlineutils'
        }
        #endregion ### 2. INSTALL AND SETUP ###


        #region ### 3. IMPLEMENT POST INSTALL CONFIGURATION ###
        # 3A i. Executes batch scripts used to install the SQL database used by PI Vision
        xPIVisionSQLConfig InstallPIVSDB {
            SQLServerName        = $DefaultSqlServer
            PIVisionDBName       = $VisionDBName
            ServiceAccountName   = "$DomainNetBiosName\$PIVSSvcAccountUsername"
            PIHOME64             = $PIHOME64
            Ensure               = 'Present'
            PsDscRunAsCredential = $domainRunAsCredential
            DependsOn            = "[xPIVisionInstall]InstallPIVision"
        }

        # 3A ii. If a load balancer DNS record is passed, then will initiate replication of PIVision to SQL Secondary.
        if ($deployHA -eq 'true' -and $env:COMPUTERNAME -eq $VSPrimary) {

            # Need to added PI Vision service account login on secondary. When the scripts to create the PIVS database are run, this login is only added to the SQL primary.
            # The SQL login for the service account does not get replicated when added to the AG, therefore need to manually add the login on the SQL secondary.
            SqlServerLogin AddPIVisionSvc {
                Ensure               = 'Present'
                Name                 = "$DomainNetBiosName\$PIVSSvcAccountUsername"
                LoginType            = 'WindowsUser'
                ServerName           = $SQLSecondary
                InstanceName         = 'MSSQLSERVER'
                PsDscRunAsCredential = $domainRunAsCredential
            }

            # Required when placed in an AG
            SqlDatabaseRecoveryModel $VisionDBName {
                InstanceName         = 'MSSQLServer'
                Name                 = $VisionDBName
                RecoveryModel        = 'Full'
                ServerName           = $DefaultSqlServer
                PsDscRunAsCredential = $domainRunAsCredential
                DependsOn            = '[xPIVisionInstall]InstallPIVision'
            }

            # Adds PIVision Database to AG and replicas to secondary SQL Server.
            SqlAGDatabase AddPIDatabaseReplicas {
                AvailabilityGroupName = $sqlAlwaysOnAvailabilityGroupName
                BackupPath            = "\\$DefaultSqlServer\Backup"
                DatabaseName          = $VisionDBName
                InstanceName          = 'MSSQLSERVER'
                ServerName            = $DefaultSqlServer
                Ensure                = 'Present'
                PsDscRunAsCredential  = $domainRunAsCredential
                DependsOn             = '[xPIVisionInstall]InstallPIVision', "[SqlDatabaseRecoveryModel]$VisionDBName"
            }
        }

        # 3B. Update PI Vision web.config (Set target PI Data Archive used by PI Vision)
        xWebConfigKeyValue ConfigAllowedPIDataArchives {
            ConfigSection = 'AppSettings'
            Key           = 'PIServersAllowed'
            WebsitePath   = "IIS:\Sites\Default Web Site\PIVision\"
            Value         = $allowedDAServers
            Ensure        = 'Present'
            IsAttribute   = $false
            DependsOn     = "[xPIVisionInstall]InstallPIVision"
        }

        # 3C. Updates PI Vision configuration with target SQL server and database.
        xPIVisionConfigFile UpdateSqlForVision {
            SQLServerName  = $FDSQLDBSERVER
            PIVisionDBName = $VisionDBName
            PIHOME64       = $PIHOME64
            Ensure         = 'Present'
            DependsOn      = "[xPIVisionInstall]InstallPIVision"
        }

        # 3D i. Post Install Configuration - Update App Pool service account for Admin site.
        # Known issue with App Pool failing to start: https://github.com/PowerShell/xWebAdministration/issues/301
        # (Suspect passwords with double quote characters break this resource with version 1.18.0.0.)
        xWebAppPool PIVisionAdminAppPool {
            Name         = 'PIVisionAdminAppPool'
            autoStart    = $true
            startMode    = 'AlwaysRunning'
            identityType = 'SpecificUser'
            Credential   = $domainSvcCredential
            Ensure       = 'Present'
            #State        = 'Started'
            DependsOn    = "[xPIVisionInstall]InstallPIVision"
        }

        # 3D ii.Post Install Configuration - Update App Pool service account for Service.
        # Known issue with App Pool failing to start: https://github.com/PowerShell/xWebAdministration/issues/301
        # (Suspect passwords with double quote characters break this resource with version 1.18.0.0.)
        xWebAppPool PIVisionServiceAppPool {
            Name         = 'PIVisionServiceAppPool'
            autoStart    = $true
            startMode    = 'AlwaysRunning'
            identityType = 'SpecificUser'
            Credential   = $domainSvcCredential
            Ensure       = 'Present'
            #State       = 'Started'
            DependsOn    = "[xPIVisionInstall]InstallPIVision"
        }

        # 3D iii.Post Install Configuration - Update App Pool service account for Service.
        # Known issue with App Pool failing to start: https://github.com/PowerShell/xWebAdministration/issues/301
        # (Suspect passwords with double quote characters break this resource with version 1.18.0.0.)
        xWebAppPool PIVisionUtilityAppPool {
            Name         = 'PIVisionUtilityAppPool'
            autoStart    = $true
            startMode    = 'AlwaysRunning'
            identityType = 'SpecificUser'
            Credential   = $domainSvcCredential
            Ensure       = 'Present'
            #State       = 'Started'
            DependsOn    = "[xPIVisionInstall]InstallPIVision"
        }

        # 3F ii. xWebAppPool resource throws error when 'state = started' and account us updated. Need script resource to start it if it's stopped. Issuing IIS reset to start all services.
        # See: https://github.com/PowerShell/xWebAdministration/issues/230
        [string[]]$appPools = @('PIVisionAdminAppPool', 'PIVisionServiceAppPool', 'PIVisionUtilityAppPool')
        ForEach ($pool in $appPools) {
            Script "Start$pool" {
                GetScript  = {
                    $state = (Get-WebAppPoolState -Name $using:pool).Value
                    return @{
                        Result = $state
                    }
                }
                TestScript = {
                    $state = (Get-WebAppPoolState -Name $using:pool).Value
                    if ($state -ne 'Started') {
                        Write-Verbose -Message "The AppPool $using:pool is stopped. $pool needs starting."
                        $false
                    }
                    else {
                        Write-Verbose -Message "AppPool $using:pool is running."
                        $true
                    }
                }
                SetScript  = {
                    Write-Verbose -Message "Starting AppPool $using:pool"
                    Start-sleep -Seconds 3
                    $result = Start-Process -FilePath "$env:windir\system32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "iisreset" -WorkingDirectory "$env:windir\system32\WindowsPowerShell\v1.0\" -RedirectStandardOutput "C:\IisResetOutput.txt" -RedirectStandardError "C:\IisError.txt"
                    $exitCode = $result.ExitCode
                    Write-Verbose -Message "Exit Code: $exitCode"
                    Write-Verbose -Message "AppPool $using:pool is now running."
                    Start-Sleep -Seconds 3
                }
                DependsOn  = "[xPIVisionInstall]InstallPIVision"
            }
        }

        ## 3F iii. Set Authentication - Commands to set Kernel Mode configuration and use AppPool Cred to true.
        # While PI Vision documentation states to disable kernel mode, the better practice is to leave it enabled to improve performance.
        # To do this, we need to allow the use of the AppPoolCreds for authentication. This can be done using the cmdline tool appcmd.exe and the config shown below.
        Script EnableKernelModeAndUseAppPoolCreds {

            GetScript  = {
                # Use appcmd.exe to check if entries are present.
                $cmd = "$env:windir\system32\inetsrv\appcmd.exe"
                $useKernelMode = &$cmd list config "Default Web Site/PIVision" -section:windowsAuthentication /text:useKernelMode
                $useAppPoolCredentials = &$cmd list config "Default Web Site/PIVision" -section:windowsAuthentication /text:useAppPoolCredentials
                return @{
                    Result = "KernelMode=$useKernelMode and useAppPoolCreds=$useAppPoolCredentials."
                }
            }

            TestScript = {
                # Use appcmd.exe to check if entries are present and set to true.
                Write-Verbose -Message "Checking 'useKernelMode' and 'useAppPoolCredentials' are set to true."
                [int]$inState = $null
                $cmd = "$env:windir\system32\inetsrv\appcmd.exe"
                &$cmd list config 'Default Web Site/PIVision' -section:windowsAuthentication /text:* |
                ForEach-Object -Process {
                    if ($_ -match 'useKernelMode:"true"') {
                        # Entry found and set to TRUE. Increment counter.
                        Write-Verbose -Message "Match Found: $_" -Verbose
                        $inState++
                    }
                    elseif ($_ -match 'useAppPoolCredentials:"true"') {
                        # Entry found and set to TRUE. Increment counter.
                        Write-Verbose -Message "Match Found: $_" -Verbose
                        $inState++
                    }
                    elseif ($_ -match 'useKernelMode:"false"') {
                        # Entry found but set to FALSE.
                        Write-Verbose -Message "Match Found: $_" -Verbose
                    }
                    elseif ($_ -match 'useAppPoolCredentials:"false"') {
                        # Entry found but set to FALSE.
                        Write-Verbose -Message "Match Found: $_" -Verbose
                    }
                }

                switch ($inState) {
                    2 { Write-Verbose -Message 'BOTH useKernelMode AND useAppPoolCredentials = TRUE.'; return $true }
                    1 { Write-Verbose -Message 'ONLY useKernelMode OR useAppPoolCrednetial = TRUE'; return $false }
                    0 { Write-Verbose -Message 'BOTH useKernelMode AND useAppPoolCrednetial = FALSE or ABSENT'; return $false }
                }
                [int]$inState = $null

            }

            SetScript  = {
                Write-Verbose -Message "Setting 'useKernelMode' to true."
                Start-Process -FilePath "$env:windir\system32\inetsrv\appcmd.exe" -ArgumentList 'set config "Default Web Site/PIVision" -section:windowsAuthentication /useKernelMode:"True" /commit:apphost' -WorkingDirectory "$env:windir\system32\inetsrv" -RedirectStandardOutput 'C:\KernelModeSetOutput.txt' -RedirectStandardError 'C:\KernelModeSetError.txt'
                Write-Verbose -Message "Setting 'useKernelMode' to true completed"

                Start-Sleep -Seconds 3

                Write-Verbose -Message "Setting 'useAppPoolCredentials' to true."
                Start-Process -FilePath "$env:windir\system32\inetsrv\appcmd.exe" -ArgumentList 'set config "Default Web Site/PIVision" -section:windowsAuthentication /useAppPoolCredentials:"True" /commit:apphost' -WorkingDirectory "$env:windir\system32\inetsrv" -RedirectStandardOutput 'C:\KernelModeSetOutput.txt' -RedirectStandardError 'C:\KernelModeSetError.txt'
                Write-Verbose -Message "Setting 'useAppPoolCredentials' to true completed."

                Start-Sleep -Seconds 3
            }
        }
        #endregion ### 3. IMPLEMENT POST INSTALL CONFIGURATION ###

        #region 4. Deployment Test Firewall Rules
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
            Name    = 'File and Printer Sharing (Echo Request - ICMPv4-In)'
            Ensure  = 'Present'
            Enabled = 'True'
        }   
        #endregion
    }
}
# SIG # Begin signature block
# MIIpTQYJKoZIhvcNAQcCoIIpPjCCKToCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDQlDYA4rAdAB1s
# 9h+8pL8tNir4GayebKay9/FcO4QYtqCCDhkwggawMIIEmKADAgECAhAIrUCyYNKc
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBeQv9ZRXH9fr7PlfICyxK81yXEf0HSK
# QJZH9tJuCBC4MDIGCisGAQQBgjcCAQwxJDAioSCAHmh0dHA6Ly90ZWNoc3VwcG9y
# dC5vc2lzb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAgBFbaUZGkFME9PIT3q9zPQG
# 2Pfysh7TYn02/uL9Nm3FUCneV72xZakKO4uyA3Gnh/T8aehuTsjeKJ6ky7msQ2mT
# 7qjLcH8k90RBqZYC5XJF0mqdJ224KFAaaarwhXuCoLdwG7jFFXIG/ybFvsS/B4Sn
# Fy03EFulnp0sPq/soOeYPwMM2KIb2zFZ+we6xRQ1dwunP/S0quhVvMxH7JWxf+J+
# 6SD9BUYkQ8Hm3WkqB5QsKnQqun2zovY3Dbi36nKiKiVSQkeERhzK1LvnIeqFjfUo
# ewQi0LE32CktDXObYz+2xo5AD8nK+H5uP/mX3MlLvbJ1RyVcl57MmDvVkqy8Felh
# IcpnguDs6BDEo00vpfZxUK9JMFWPff8Tn2oemBbiZQTFiQzxG0Rq7nVk8IP3DoKj
# EqnS6gL8tjbSNFEJttJb5en9G7zBshMhz/yVCphpWlGVqWCoITnz3XWJG65lhiEE
# ZMsFfA2qx1k576ORoGh5+hJfBqOEN/xhYIV9hzrhxIyPS/OlLkzkqIxj1V2wPVa5
# QZIm+mEhqcgPcxQ1LtF///pTKSW3mAAlZhURwf8Gommrdi10CBjyeVt8Oshv95Rg
# AMipq4rTLDiwHCn2gyUhL37KIOUTwaJEQPN+0KyY+RWdegBy/hUneQ8n6mAFZjHA
# kGsrhuZ3kJjGCj5MbMIJmKGCFz0wghc5BgorBgEEAYI3AwMBMYIXKTCCFyUGCSqG
# SIb3DQEHAqCCFxYwghcSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQ
# AQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCCrzCx3O5WI
# c6SG05aAKpHAt9l6CfK6CfjD4kaWnYG+ogIQaY5LEXkO1p7LPC4F2sqCbxgPMjAy
# MjEwMjExODIxMDJaoIITBzCCBsAwggSooAMCAQICEAxNaXJLlPo8Kko9KQeAPVow
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
# MTgyMTAyWjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBTzhyJNhjOCkjWplLy9j5bp
# /hx8czAvBgkqhkiG9w0BCQQxIgQgBxAUqOBRW77YzE7+l1a8gCa65hwE9vruz0DQ
# 36/Ugx8wNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgx/ThvjIoiSCr4iY6vhrE/E/m
# eBwtZNBMgHVXoCO1tvowDQYJKoZIhvcNAQEBBQAEggIAEIxJ/rxUnylqOHvAqdFO
# OCutKA3pBNRz1CepI4+QcLp0AevtZ2ePjUDKYWXaJmXJY6E9P11A8d96VO2BDVGj
# nNqgk5+LesObugQ8N5NvI0JOsQn6VvR9TwqE0CMHKe5K179SomDCHFLBHKugIumG
# dxglXRRPd0MgOOxwcesOYJaskj+inLe6FmgmBrqjgpT+/JNVoUdttq0Cyxvcp6nU
# R6FecoCkNWrndxSjqVTVeEMudoZ2pjM4HQILUjfOoVk/Lq1CnyqRbv/oyWAZ4Tib
# DM0DwFqigZYfrteoemODfqGezCJl2RNEslh4SnavTrX6hFZ4VyEmGtB/LV+skliE
# ryb+AAK/C64Figsg3k0TlNNi1Osj5Z3+OArOG53qrRMvMWxxZ+TK+O+08mu9MLwR
# Zm7FanAx61ZMaeL9L1++x2BxtmlUJZFkyone1J51lYWA97YZ3eGAZ+3kmZ0xvSHP
# /ei298MT0hjXpJW3RXa66ST25hBadaKwGk12+Uy/rvsSpzp1Kr6bTx6pJ/nsf2W7
# rTJWqHcVsSQM0CtR0QFeVUYxOJh0TCGVBwWaf64P5/prhZr8h4Aq1wVohpuijSez
# zrtKfliCEOanPos1vSmwptLJSMgXvurR+P/V3w/rI55LAnZh63MDT5Ff48RPEAKB
# i6RzrN/5mbOTLaOV3+ZfT7w=
# SIG # End signature block
