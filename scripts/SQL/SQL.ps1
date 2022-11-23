Configuration SQL
{
    param(
    [Parameter(Mandatory = $true)]
    [pscredential]$Credential,

    [Parameter(Mandatory = $true)]
    [pscredential]$SQLCredential,

    [Parameter(Mandatory = $true)]
    [string]$namePrefix,

    [Parameter(Mandatory = $true)]
    [string]$nameSuffix,

    [Parameter(Mandatory = $true)]
    [string]$SQLPrimary,

    [Parameter(Mandatory = $true)]
    [string]$SQLSecondary,

    [Parameter(Mandatory = $true)]
    [string]$deployHA,

    [Parameter(Mandatory = $true)]
    [string]$PrimaryDomainController,

    [Parameter(Mandatory = $true)]
    [string]$DomainNetBiosName,

    # Used by Cluster Resource (i.e. AG Listener)
    [Parameter(Mandatory = $true)]
    [String]$lbIP,

    # Used by Cluster Cloud Witness
    [Parameter(Mandatory = $true)]
    [String]$witnessStorageAccount,

    # Used by Cluster Cloud Witness
    [Parameter(Mandatory = $true)]
    [String]$witnessStorageAccountKey
    <#
    Array of hashtables in the form:
    @(@{Name='domain\myuser';LoginType='WindowsUser'},@{Name='domain\mygroup';LoginType='WindowsGroup'})
    #>
    )
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'StorageDsc'
    Import-DscResource -ModuleName 'xStorage'
    Import-DscResource -ModuleName 'xNetworking'
    Import-DscResource -ModuleName 'SqlServerDsc'
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xActiveDirectory'
    Import-DscResource -ModuleName 'xFailOverCluster'
    Import-DscResource -ModuleName 'cNtfsAccessControl'
    Import-DscResource -ModuleName 'xSmbShare'

    $SQLAdminLogin = @(@{Name="$($namePrefix)\$($Credential.UserName)";LoginType='WindowsUser';ServerRole='sysadmin'})
    $ClusterOwnerNode = $SQLSecondary
    $ClusterName = $namePrefix + "-sqlclstr" + $nameSuffix
    $sqlAlwaysOnAvailabilityGroupName = $namePrefix + '-sqlag' + $nameSuffix
    $defaultEmptyDb = 'EmptyDB'

    [System.Management.Automation.PSCredential]$RunCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$namePrefix\$($Credential.UserName)", $Credential.Password)
    [System.Management.Automation.PSCredential]$SqlDomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$namePrefix\$($SQLCredential.UserName)", $SQLCredential.Password)

    Node localhost
    {
    #region ### 1. VM PREPARATION ###
    # Wait for Data Disk availability
    xWaitforDisk Volume_F {
        DiskID           = 2
        retryIntervalSec = 30
        retryCount       = 20
    }

    # Format Data Disk
    xDisk Volume_F {
        DiskID      = 2
        DriveLetter = 'F'
        FSFormat    = 'NTFS'
        FSLabel     = 'Data'
        DependsOn   = '[xWaitforDisk]Volume_F'
    }

    File DataDirectory {
        Type = 'Directory'
        DestinationPath = 'F:\Data'
        Ensure = "Present"
        DependsOn   = '[xDisk]Volume_F'
    }

    # Wait for Data Disk availability
    xWaitforDisk Volume_G {
        DiskID           = 3
        retryIntervalSec = 30
        retryCount       = 20
    }

    # Format Data Disk
    xDisk Volume_G {
        DiskID      = 3
        DriveLetter = 'G'
        FSFormat    = 'NTFS'
        FSLabel     = 'Logs'
        DependsOn   = '[xWaitforDisk]Volume_G'
    }

    File LogDirectory {
        Type = 'Directory'
        DestinationPath = 'G:\Log'
        Ensure = "Present"
        DependsOn   = '[xDisk]Volume_G'
    }

    # Wait for Data Disk availability
    xWaitforDisk Volume_H {
        DiskID           = 4
        retryIntervalSec = 30
        retryCount       = 20
    }

    # Format Data Disk
    xDisk Volume_H {
        DiskID      = 4
        DriveLetter = 'H'
        FSFormat    = 'NTFS'
        FSLabel     = 'Backups'
        DependsOn   = '[xWaitforDisk]Volume_H'
    }

    File BackupDirectory {
        Type = 'Directory'
        DestinationPath = 'H:\Backup'
        Ensure = "Present"
        DependsOn   = '[xDisk]Volume_H'
    }

    # Opening up ports 1433 and 1434 for SQL
    xFirewall DatabaseEngineFirewallRule
    {
        Direction   = 'Inbound'
        Name        = 'SQL-Server-Database-Engine-TCP-In'
        DisplayName = 'SQL Server Database Engine (TCP-In)'
        Description = 'Inbound rule for SQL Server to allow TCP traffic for the Database Engine.'
        Group       = 'SQL Server'
        Enabled     = 'True'
        Protocol    = 'TCP'
        LocalPort   = '1433'
        Ensure      = 'Present'
    }

    # Opening up ports 1433 and 1434 for SQL
    xFirewall SQLBrowserFirewallRule
    {
        Direction   = 'Inbound'
        Name        = 'SQL-Browser-Service-UDP-In'
        DisplayName = 'SQL Browser Service (UDP-In)'
        Description = 'Inbound rule for SQL Server to allow the use of the SQL Browser service'
        Group       = 'SQL Server'
        Enabled     = 'True'
        Protocol    = 'UDP'
        LocalPort   = '1434'
        Ensure      = 'Present'
    }

    xFirewall WMIFirewallRule
    {
        Direction = 'Inbound'
        Name = 'Windows Management Instrumentation (DCOM-In)'
        Enabled     = 'True'
    }
    #endregion ### 1. VM PREPARATION ###

    #region ### 2. INSTALL, SETUP, and LOGINS ###
    SqlServerNetwork 'EnableTcpStaticPort'
    {
        InstanceName = 'MSSQLSERVER' #used to be 'SQLEXPRESS' - Alex Oct 9 2018 14:43
        ProtocolName = 'tcp'
        IsEnabled = $true
        TcpDynamicPort = $false
        TcpPort = '1433'
        RestartService = $true
    }

    xService 'BrowserService'
    {
        Name = 'SQLBrowser'
        StartupType = 'Automatic'
        State = 'Running'
    }

    WindowsFeature ADPS {
        Name   = 'RSAT-AD-PowerShell'
        Ensure = 'Present'
    }

    if ($env:COMPUTERNAME -eq $SQLPrimary) {
        # 2A ii - To have the PI AF SQL Database work with SQL Always On, we use a domain group "AFSERVERS" instead of a local group.
        # This requires a modification to the AF Server install scripts per documentation:
        # This maps the SQL User 'AFServers' maps to this domain group instead of the local group, providing security mapping consistency across SQL nodes.
        xADGroup CreateAFServersGroup {
            GroupName   = 'AFServers'
            Description = 'Service Accounts with Access to PIFD databases'
            Category    = 'Security'
            Ensure      = 'Present'
            GroupScope  = 'Global'
            Credential  = $RunCredential
            DomainController = $PrimaryDomainController
            DependsOn   = '[WindowsFeature]ADPS'
        }

        Script WaitForADGroup
        {
            GetScript = {$false}
            TestScript = {$false}
            SetScript = {
                #Wait for AD to create the group
                Start-Sleep -s 60
            }
            DependsOn = '[xADGroup]CreateAFServersGroup'
        }

        # 2E ii - Add Domain AFSERVERS group as Sql Login
        SQLServerLogin AddAFServersGroupToPublicServerRole {
            Name                 = "$namePrefix\AFServers"
            LoginType            = 'WindowsGroup'
            ServerName           = $env:COMPUTERNAME
            InstanceName         = 'MSSQLSERVER'
            Ensure               = 'Present'
            PsDscRunAsCredential = $Credential
            DependsOn            = '[Script]WaitForADGroup'
        }
    }
    else {
        # 2E ii - Add Domain AFSERVERS group as Sql Login
        SQLServerLogin AddAFServersGroupToPublicServerRole {
            Name                 = "$namePrefix\AFServers"
            LoginType            = 'WindowsGroup'
            ServerName           = $env:COMPUTERNAME
            InstanceName         = 'MSSQLSERVER'
            Ensure               = 'Present'
            PsDscRunAsCredential = $Credential
        }
    }

    # Adding domain sysadmin to SQL
    SQLServerLogin 'AdminLogin'
    {
        ServerName = 'localhost'
        InstanceName = 'MSSQLSERVER'
        Name = $SQLAdminLogin.Name
        LoginType = $SQLAdminLogin.LoginType
        PsDscRunAsCredential = $Credential
    }

    SQLServerRole 'AdminRole' {
        ServerRoleName       = $SQLAdminLogin.ServerRole
        MembersToInclude     = $SQLAdminLogin.Name
        ServerName           = 'localhost'
        InstanceName         = 'MSSQLSERVER'
        PsDscRunAsCredential = $Credential
    }

    SqlDatabaseDefaultLocation Set_SqlDatabaseDefaultDirectory_Data
    {
        ServerName              = $env:COMPUTERNAME
        InstanceName			= 'MSSQLSERVER'
        ProcessOnlyOnActiveNode = $true
        Type                    = 'Data'
        Path                    = 'F:\DATA'
        PsDscRunAsCredential    = $RunCredential
        DependsOn   = '[File]DataDirectory'
    }

    SqlDatabaseDefaultLocation Set_SqlDatabaseDefaultDirectory_Log
    {
        ServerName              = $env:COMPUTERNAME
        InstanceName			= 'MSSQLSERVER'
        ProcessOnlyOnActiveNode = $true
        Type                    = 'Log'
        Path                    = 'G:\LOG'
        PsDscRunAsCredential    = $RunCredential
        DependsOn   = '[File]LogDirectory'
    }

    SqlDatabaseDefaultLocation Set_SqlDatabaseDefaultDirectory_Backup
    {
        ServerName              = $env:COMPUTERNAME
        InstanceName			= 'MSSQLSERVER'
        ProcessOnlyOnActiveNode = $true
        RestartService			= $true
        Type                    = 'Backup'
        Path                    = 'H:\BACKUP'
        PsDscRunAsCredential    = $RunCredential
        DependsOn   = '[File]BackupDirectory'
    }

    if ($env:COMPUTERNAME -eq $SQLPrimary) {
        SqlDatabase EmptyDB {
            Ensure       = 'Present'
            ServerName   = $env:COMPUTERNAME
            Name         = $defaultEmptyDb
            InstanceName = 'MSSQLServer'
        }

        # 2B: AG Databases need to be set to Full Recovery Model
        SqlDatabaseRecoveryModel EmptyDBFullRecovery {
            Name                 = $defaultEmptyDb
            RecoveryModel        = 'Full'
            ServerName           = $env:COMPUTERNAME
            InstanceName         = 'MSSQLServer'
            PsDscRunAsCredential = $RunCredential
            DependsOn            = '[SqlDatabase]EmptyDB'
        }
    }

    SqlServerLogin AddNTServiceClusSvc {
        Ensure               = 'Present'
        Name                 = ($namePrefix+'\'+$SQLCredential.UserName)
        LoginType            = 'WindowsUser'
        ServerName           = $env:COMPUTERNAME
        InstanceName         = 'MSSQLSERVER'
        PsDscRunAsCredential = $Credential
    }

    # 2 D ii.Add the required permissions to the cluster service login
    SqlServerPermission AddNTServiceClusSvcPermissions {
        Ensure               = 'Present'
        ServerName           = $env:COMPUTERNAME
        InstanceName         = 'MSSQLSERVER'
        Principal            = $SqlDomainCredential.UserName
        Permission           = 'AlterAnyAvailabilityGroup', 'ViewServerState'
        PsDscRunAsCredential = $RunCredential
        DependsOn            = '[SqlServerLogin]AddNTServiceClusSvc'
    }


    # Need to add SQL Server Service Account with permissions to access HADR, otherwise replication will fail.
    SqlServerEndpointPermission SQLConfigureEndpointPermission {
        Ensure               = 'Present'
        ServerName           = $env:COMPUTERNAME
        InstanceName         = 'MSSQLSERVER'
        Name                 = 'Microsoft SQL VM HA Container Mirroring Endpoint'
        Principal            = $SqlDomainCredential.UserName
        Permission           = 'CONNECT'
        PsDscRunAsCredential = $RunCredential
    }

    Script RefreshFileSystem
    {
        GetScript = {$false}
        TestScript = {$false}
        SetScript = {Get-PSDrive -PSProvider FileSystem}
    }

    # Set SQL Server Service Account permissions on transfer folder.
    cNtfsPermissionEntry TransferFolderPermissions {
        Ensure                   = 'Present'
        Path                     = 'H:\BACKUP'
        Principal                = $SqlDomainCredential.UserName
        AccessControlInformation = @(
            cNtfsAccessControlInformation {
                AccessControlType  = 'Allow'
                FileSystemRights   = 'FullControl'
                Inheritance        = 'ThisFolderSubfoldersAndFiles'
                NoPropagateInherit = $false
            }
        )
        PsDscRunAsCredential = $RunCredential
        DependsOn   = '[File]BackupDirectory', '[Script]RefreshFileSystem'
    }

    # Make Backup Folder an SMB Share so DB can be transferred when setting up Always On.
    xSmbShare CreateBackupShare {
        Name        = 'Backup'
        Path        = 'H:\BACKUP'
        Description = 'Used for DB backups and transfers setting up AG'
        Ensure      = 'Present'
        FullAccess  = @('Domain Admins', $SQLAdminLogin.Name, $SqlDomainCredential.UserName)
        DependsOn   = '[cNtfsPermissionEntry]TransferFolderPermissions'
    }


    if ( $env:COMPUTERNAME -eq $SQLPrimary ) {
        # 2G a. PRIMARY: Create the availability group on the instance tagged as the primary replica
        SqlAG CreateAG {
            Ensure               = 'Present'
            Name                 = $sqlAlwaysOnAvailabilityGroupName
            InstanceName         = 'MSSQLSERVER'
            ServerName           = $SQLPrimary
            AvailabilityMode     = 'SynchronousCommit'
            FailoverMode         = 'Automatic'
            PsDscRunAsCredential = $RunCredential
        }

            SqlAGListener CreateSqlAgListener {
                Ensure               = 'Present'
                ServerName           = $SQLPrimary
                InstanceName         = 'MSSQLSERVER'
                AvailabilityGroup    = $sqlAlwaysOnAvailabilityGroupName
                Name                 = 'AG0-Listener'
                IpAddress            = "$lbIP/255.255.255.128"
                Port                 = 1433
                DependsOn            = '[SqlAG]CreateAG'
                PsDscRunAsCredential = $RunCredential
            }
        }
        else {
                # 2G b i. SECONDARY: Waiting for the Availability Group role to be present.
                SqlWaitForAG WaitAG {
                    Name                 = $sqlAlwaysOnAvailabilityGroupName
                    RetryIntervalSec     = 60
                    RetryCount           = 30
                    PsDscRunAsCredential = $RunCredential
                    #DependsOn            = '[SqlAlwaysOnService]EnableAlwaysOn'
                }

                # 2G b ii. Add replica to the availability group already create on the primary node.
                SqlAGReplica AddReplica {
                    Ensure                     = 'Present'
                    Name                       = $env:COMPUTERNAME
                    AvailabilityGroupName      = $sqlAlwaysOnAvailabilityGroupName
                    ServerName                 = $env:COMPUTERNAME
                    InstanceName               = 'MSSQLSERVER'
                    PrimaryReplicaServerName   = $SQLPrimary
                    PrimaryReplicaInstanceName = 'MSSQLSERVER'
                    AvailabilityMode           = 'SynchronousCommit'
                    FailoverMode               = 'Automatic'
                    PsDscRunAsCredential       = $RunCredential
                    DependsOn                  = '[SqlServerLogin]AddNTServiceClusSvc', '[SqlServerPermission]AddNTServiceClusSvcPermissions', '[SqlWaitForAG]WaitAG'
                }
            }

            If ($env:COMPUTERNAME -eq $SQLPrimary) {
                Script SetListenerProbePort {
                    GetScript = {
                        Return @{$ProbeIP = (Get-ClusterResource | Where-Object {$_.Name -eq "$using:sqlAlwaysOnAvailabilityGroupName`_$using:lbIP"} | Get-ClusterParameter | Where-Object {$_.Name -eq "ProbePort"}).Value}
                    }

                    TestScript = {
                        if ($ProbeIP -eq '59999') {
                            Write-Verbose -Message "The listener associated with $using:sqlAlwaysOnAvailabilityGroupName already uses the correct port - 59999"
                            return $true
                        }
                        else {
                            Write-Verbose -Message "The listener associated with $using:sqlAlwaysOnAvailabilityGroupName is not using the correct port - 59999"
                            return $false
                        }
                    }

                    SetScript = {
                        (Get-ClusterResource | Where-Object {$_.Name -eq "$using:sqlAlwaysOnAvailabilityGroupName`_$using:lbIP"}) | Set-ClusterParameter -Name "ProbePort" -Value 59999
                        Restart-Service -Name ClusSvc
                    }

                PsDscRunAsCredential = $RunCredential
                DependsOn            = '[SqlAGListener]CreateSqlAgListener'
                }
            }

            If ($env:COMPUTERNAME -eq $SQLSecondary) {
                SqlAGDatabase AddPIDatabaseReplicas {
                    AvailabilityGroupName = $sqlAlwaysOnAvailabilityGroupName
                    BackupPath            = "\\$SQLPrimary\BACKUP"
                    DatabaseName          = $defaultEmptyDb
                    InstanceName          = 'MSSQLSERVER'
                    ServerName            = $SQLPrimary
                    Ensure                = 'Present'
                    PsDscRunAsCredential  = $RunCredential
                }
        }
    }
}
# SIG # Begin signature block
# MIIpTQYJKoZIhvcNAQcCoIIpPjCCKToCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDJt9TA1l2QzBeW
# oZ53K/+VzDyviUmCvblu6KIKCssdsaCCDhkwggawMIIEmKADAgECAhAIrUCyYNKc
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINjL3mPDur/m+Ms3Azh96LDMqVauey81
# bKDmkHeZFFuBMDIGCisGAQQBgjcCAQwxJDAioSCAHmh0dHA6Ly90ZWNoc3VwcG9y
# dC5vc2lzb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAgCx+kS1SFLeYccvUZJGwRl6
# xb+9KHqHJkPCVKgxgHYcg2P83aB6b5ySav96dNMmZqy8Z8nPSuqxZhjslMj58D15
# JM4tUtNIsFSxW5nKbx40O7RcL9cq8g1ZDzgsGU0KBW6EpALgDCpTPSKNKxx4Uq/9
# Ukf3p+VMjiehyFRgXTqtxJzvl2v1dSous2IczwXlydVcLoXnbG8xycl07AiPG17e
# 7z/vOjKV6pTl44NiJIxTykmXlvY+1kiBX05dt/BkBvNWm9UDHif4F0PwWDqq5Ra/
# QDGcoRBJNg0gwBxiI5WXBn4oKfADoBRdb3wYRIslm38wWAOsBFpMH0+wvcGOIpIx
# njuxXVrvFgkWciVp2LPiwxyUjpfLkU4jRzR3EpIJyre1hQnDoWzjfXXq3+X2HsK1
# LuY+y554m9lNDBKM9vbeV78yBbW+BLnRy/B4Qt5TE12IAtwdBLSlOObcsi4APi1F
# Ve1e/M/7d7wuEtnsP97eQdSA4fd0NVFI51s9nUSWhHz0MF25nUhmQo8Ptz5zclQQ
# xm0ggEHUl+SuZaPTYl0dme//S6X5EzO4+OHtcLM8FGPf4oD0dfgnMVCJmeE9nLFC
# ZhZzzK8Hd72MzBEOn89vjQLUhQILIGsgnfsjuBP9tV69TEJB09K2Q6zWbCd1EnTh
# 4ULHpd2kSOPIDthaXvA5nqGCFz0wghc5BgorBgEEAYI3AwMBMYIXKTCCFyUGCSqG
# SIb3DQEHAqCCFxYwghcSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQ
# AQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCBwUaSD5Rk4
# bfyrQaJwf/16OsYjAHpZwFuoDJT8J/UeZwIQWcYccWgcGvLbn20A+JnB0BgPMjAy
# MjEwMjExODIxMDRaoIITBzCCBsAwggSooAMCAQICEAxNaXJLlPo8Kko9KQeAPVow
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
# MTgyMTA0WjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBTzhyJNhjOCkjWplLy9j5bp
# /hx8czAvBgkqhkiG9w0BCQQxIgQgxP3NOvzqdkn8J4zp71AXbAAjCXCVO75GA4S6
# KO5GuDgwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgx/ThvjIoiSCr4iY6vhrE/E/m
# eBwtZNBMgHVXoCO1tvowDQYJKoZIhvcNAQEBBQAEggIAIZNuLjAmiFjf4IELSQer
# oNXYh/pLFmPLmZWE4C/qJFnWzZS1JYNO/FKSEornlFgmvozgrN3VgE5fi0l05J+3
# n8ymoBhLNy1Us0tVvJhoSDyK+a8Xh9EClPfhSoWXZCrCDMUkSWNyR6JPBNk811NX
# 96zn/fdL6/XRTNu+oPinLbv0YQxoWvhWHOOxfDO938yJS0YnmenEqf2fKpfSZ1GQ
# SoOF9sD3rJh0NJh/49ppmqHuSZAiGk1HkzYCe5IUmaNLD4lBGa3n2D6sNWaXDYIF
# oekyUuE50WNeWljBFIGGfjeQO7g3/Ua93NvkOJDJXUVWqHs8qciNpGlYNLyp2UPc
# lmZmyIGcNbU3x0dqidTSlbDLFfqZqbcxJfxS3YHF/uy9cNOUAjvCsZYsAflhQDqh
# 2d2VD6q5qazkySxXcJRFxzlm3uXRWI8ZqfJoXf670eo0CPeYYyZEL8hV90ip1ObO
# iUNpDGX3tCkE80ssgvQ2IaE/RfhljE3eMnlsTyqadYH4hgc5zjI9jRRcdYUnZtFh
# 2FeWhv9JbtpnPvIQahEN6lQ13k/ZJuynUg9vCiMq8krKEwspbRh7tPIO0z2Mhk42
# Loe7TWsDABkBK2rSQ72u2Jtp4uxKefO8AhG6aJEeI592ggxM+ZzEIQtTmufQLrTG
# DnwmoujbOz2NxB1Zfmz70yI=
# SIG # End signature block
