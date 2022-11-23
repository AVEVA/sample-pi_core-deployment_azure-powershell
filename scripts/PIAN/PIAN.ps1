Configuration PIAN
{
    param(
        # PI Analysis Default settings
        [string]$PIPath,
        [string]$PIProductID,

        [Parameter(Mandatory=$true)]
        [string]$DefaultPIAFServer,
        [Parameter(Mandatory=$true)]
        [string]$DefaultPIDataArchive,
        [Parameter(Mandatory=$true)]
        [string]$PIVisionServer,        
        [Parameter(Mandatory=$true)]
        [string]$PIAnalysisServer,

        [string]$PIHOME = 'F:\Program Files (x86)\PIPC',
        [string]$PIHOME64 = 'F:\Program Files\PIPC',

        [Parameter(Mandatory=$true)]
        [PSCredential]$svcCredential,
        [pscredential]$runAsCredential,

        [Parameter(Mandatory)]
        [string]$OSIsoftTelemetry,
   
        [Parameter(Mandatory=$true)]
        [string]$TestFileName,
        [Parameter(Mandatory=$true)]
        [string]$RDSName,
        [Parameter(Mandatory=$true)]
        [string]$deployHA
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xPendingReboot
    Import-DscResource -ModuleName xStorage
    Import-DscResource -ModuleName xNetworking
    Import-DscResource -ModuleName XActiveDirectory
    Import-DscResource -ModuleName cchoco


    # Generate credential for PI Analysis Service Account
    $DomainNetBiosName = ((Get-WmiObject -Class Win32_NTDomain -Filter "DnsForestName = '$((Get-WmiObject -Class Win32_ComputerSystem).Domain)'").DomainName)

    # Extracts username only (no domain net bios name)
    $PIANSvcAccountUserName = $svcCredential.Username
    # Create credential with Domain Net Bios Name included.
    $domainServiceAccountCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ("$DomainNetBiosName\$PIANSvcAccountUserName", $svcCredential.Password)
    
    $EventLogSource = 'PISystemDeploySample'
    $DomainAdminUsername = $runAsCredential.UserName
    $TestRunnerAccount = New-Object System.Management.Automation.PSCredential -ArgumentList ("$DomainNetBiosName\$DomainAdminUsername", $runAsCredential.Password)

    Node localhost {
        
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ActionAfterReboot  = "ContinueConfiguration"
        }

        #region ### 1. VM PREPARATION ###
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

        # 1B. Open PI Analytics Firewall Rules
        xFirewall PIAFAnalysisFirewallRule {
            Direction   = 'Inbound'
            Name        = 'PI-System-PI-AF-Analysis-TCP-In'
            DisplayName = 'PI System PI AF Analysis (TCP-In)'
            Description = 'Inbound rule for PI AF Analysis to allow TCP traffic access to the PI AF Server.'
            Group       = 'PI Systems'
            Enabled     = 'True'
            Action      = 'Allow'
            Protocol    = 'TCP'
            LocalPort   = '5463'
            Ensure      = 'Present'
        }
        #endregion ### 1. VM PREPARATION ###

        #region ### 2. INSTALL AND SETUP ###
        # 2A i. Installing the RSAT tools for AD Cmdlets
        WindowsFeature ADPS {
            Name   = 'RSAT-AD-PowerShell'
            Ensure = 'Present'
        }

        # 2A ii. Create PI Analysis Service Account
        xADUser ServiceAccount_PIAN {
            DomainName                    = $DomainNetBiosName
            UserName                      = $svcCredential.Username
            CannotChangePassword          = $true
            Description                   = 'PI Analysis service account.'
            DomainAdministratorCredential = $runAsCredential
            Enabled                       = $true
            Ensure                        = 'Present'
            Password                      = $svcCredential
            DependsOn                     = '[WindowsFeature]ADPS'
        }

        # 2A iii. Add PI Analysis Service account to the AD Group mapped to the PI Identity "PIPointsAnalysisGroup"
        xADGroup CreateANServersGroup {
            GroupName        = 'PIPointsAnalysisCreator'
            Description      = 'Identity for PIACEService, PIAFService and users that can create and edit PI Points'
            Category         = 'Security'
            Ensure           = 'Present'
            GroupScope       = 'Global'
            MembersToInclude = $PIANSvcAccountUserName
            Credential       = $runAsCredential
            DependsOn        = '[WindowsFeature]ADPS'
        }

        # 2B. Installing Chocolatey to facilitate package installs.

        # Check if install directory is empty, clear it out if not
        Remove-Item C:\Choco\* -Recurse -Force
        cChocoInstaller installChoco {
            InstallDir = "C:\Choco"
        }

        # 2C. Install .NET Framework 4.8
        cChocoPackageInstaller 'dotnetfx' {
            Name     = 'dotnetfx'
            DependsOn = '[cChocoInstaller]installChoco'
        }

        xPendingReboot RebootDotNet {
            Name      = 'RebootDotNet'
            DependsOn = '[cChocoPackageInstaller]dotnetfx'
        }

        # 2D. Install PI System Client Tools
        # PI Analysis service account updated with Service resource to avoid passing plain text password.
        Package PISystem {
            Name                 = 'PI Server 2018 Installer'
            Path                 = $PIPath
            ProductId            = $PIProductID
            Arguments            = "/silent ADDLOCAL=PIAnalysisService,FD_AFExplorer,FD_AFAnalysisMgmt,PiPowerShell PIHOME=""$PIHOME"" PIHOME64=""$PIHOME64"" AFSERVER=""$DefaultPIAFServer"" PISERVER=""$DefaultPIDataArchive"" PI_ARCHIVESIZE=""1024"" SENDTELEMETRY=""$OSIsoftTelemetry"" AFACKNOWLEDGEBACKUP=""1"" PIANALYSIS_SERVICEACCOUNT=""$($domainServiceAccountCredential.username)"" PIANALYSIS_SERVICEPASSWORD=""$($domainServiceAccountCredential.GetNetworkCredential().Password)"""
            Ensure               = 'Present'
            PsDscRunAsCredential = $runAsCredential  # Admin creds due to limitations extracting install under SYSTEM account.
            ReturnCode           = 0, 3010, 1641
            DependsOn            = '[xDisk]Volume_F', '[xPendingReboot]RebootDotNet'
        }

        # Updating RunAs account for PI Analytics
        Service UpdateANServiceAccount {
            Name = 'PIAnalysisManager'
            StartupType = 'Automatic'
            State = 'Running'
            Ensure = 'Present'
            Credential = $domainServiceAccountCredential
            DependsOn = '[Package]PISystem'
        }

        # 2E. Initiate any outstanding reboots.
        xPendingReboot Reboot1 {
            Name      = 'RebootServer'
            DependsOn = '[Package]PISystem'
        }
        #endregion ### 2. INSTALL AND SETUP ###

        #region DeploymentTests
        # 3B Install visual studio 2017 build tools for tests.
        cChocoPackageInstaller 'visualstudio2017buildtools' {
            Name = 'visualstudio2017buildtools'
            DependsOn = '[cChocoInstaller]installChoco'
        }

        # 3C Obtain & Install PI Vision certificate
        Script ConfigurePIVisionAccess {
            GetScript = {
                return @{
                    Value = 'ConfigurePIVisionAccess'
                }
            }

            TestScript = {
                $FileName = $Using:TestFileName
                $TestFileNameArray = $FileName.Split('.')
                $TestDir = $TestFileNameArray[0]

                return (Test-Path -LiteralPath C:\$TestDir\testResults)
            }

            SetScript = {
                Try {
                    [Uri]$Uri  = "https://$Using:PIVisionServer" 
                    [string]$PIVSServer = "$Using:PIVisionServer.com"
                    $request = [System.Net.HttpWebRequest]::Create($uri)

                    #Get PIVision certificate
                    try
                    {
                        #Make the request but ignore (dispose it) the response, since we only care about the service point
                        $request.GetResponse().Dispose()
                    }
                    catch [System.Net.WebException]
                    {
                        if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::TrustFailure)
                        {
                            #Ignore trust failures, since we only want the certificate, and the service point is still populated at this point
                        }
                        else
                        {								
                            Write-EventLog -LogName Application -Source "$Using:EventLogSource" -EntryType Error -EventId 0 -Message  $_
                        }
                    }

                    #Install PIVision certificate
                    try {
                        #The ServicePoint object should now contain the Certificate for the site.
                        $servicePoint = $request.ServicePoint

                        $bytes = $servicePoint.Certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                        set-content -value $bytes -encoding byte -path "D:\pivs.cer"
                        Import-Certificate -FilePath D:\pivs.cer -CertStoreLocation Cert:\LocalMachine\Root
                    }
                    catch {
                        Write-EventLog -LogName Application -Source "$Using:EventLogSource" -EntryType Error -EventId 0 -Message  $_
                    }

                    #Add PIVision to trusted sites
                    try {
                        Set-Location "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                        Set-Location ZoneMap\Domains
                        New-Item $PIVSServer
                        Set-Location $PIVSServer
                        New-Item www
                        Set-Location www
                        New-ItemProperty . -Name https -Value 2 -Type DWORD

                        #Let machine trust UNC paths
                        Set-Location "HKCU:\Software\Microsoft\Windows\"
                        Set-Location "CurrentVersion"
                        Set-Location "Internet Settings"
                        Set-ItemProperty ZoneMap UNCAsIntranet -Type DWORD 1
                        Set-ItemProperty ZoneMap IntranetName -Type DWORD 1
                    }
                    catch {
    
                        Write-EventLog -LogName Application -Source "$Using:EventLogSource" -EntryType Error -EventId 0 -Message  $_
                    }
                }
                Catch {
                    Write-EventLog -LogName Application -Source "$Using:EventLogSource" -EntryType Error -EventId 0 -Message  $_
                }
            }
            DependsOn  = '[Package]PISystem', '[xPendingReboot]Reboot1'
            PsDscRunAsCredential = $TestRunnerAccount
        }

        # 3D Run tests
        Script DeploymentTests {
            GetScript = {
                return @{
                    Value = 'DeploymentTests'
                }
            }

            TestScript = {
                $FileName = $Using:TestFileName
                $TestFileNameArray = $FileName.Split('.')
                $TestDir = $TestFileNameArray[0]

                return (Test-Path -LiteralPath C:\$TestDir\testResults)
            }

            SetScript = {
                Try {
                    $FileName = $Using:TestFileName
                    $TestFileNameArray = $FileName.Split('.')
                    $TestDir = $TestFileNameArray[0]

                    # Check Event Log souce, create if not present
                    $CheckSource = Get-EventLog -LogName Application -Source "$Using:EventLogSource" -ErrorAction SilentlyContinue
                    if (!$CheckSource) {New-EventLog -LogName Application -Source "$Using:EventLogSource" -Verbose}  

                    Write-EventLog -LogName Application -Source "$Using:EventLogSource" -EntryType Information -EventId 0 -Message "Deployment tests starting. DomainName: $Using:DomainNetBiosName UserName: $Using:DomainAdminUserName TestFileName $Using:TestFileName TestDir $TestDir DefaultPIDataArchive $Using:DefaultPIDataArchive DefaultPIAFServer $Using:DefaultPIAFServer PIVisionServer $PIVisionServer PIAnalysisServer $PIAnalysisServer"

                    #Expand test zip file
                    Expand-Archive -LiteralPath "D:\$TestFileName" -DestinationPath c:\ -Force

                    #Update config that will be used for test run
                    (Get-Content C:\$TestDir\source\App.config).replace('Enter_Your_PIDataArchive_Name_Here', $Using:DefaultPIDataArchive) | Set-Content C:\$TestDir\source\Run.config
                    (Get-Content C:\$TestDir\source\Run.config).replace('Enter_Analysis_Service_Machine_Name_Here', $Using:PIAnalysisServer ) | Set-Content C:\$TestDir\source\Run.config
                    (Get-Content C:\$TestDir\source\Run.config).replace('key="PIVisionServer" value=""', "key=""PIVisionServer"" value=""https://$Using:PIVisionServer/PIVision""") | Set-Content C:\$TestDir\source\Run.config

                    $deployHA = $Using:deployHA
                    if($deployHA -eq 'false')	{
                        (Get-Content C:\$TestDir\source\Run.config).replace('Enter_Your_AFServer_Name_Here', $Using:DefaultPIAFServer) | Set-Content C:\$TestDir\source\Run.config
                    }
                    else {
                        (Get-Content C:\$TestDir\source\Run.config).replace('Enter_Your_AFServer_Name_Here', "PIAF") | Set-Content C:\$TestDir\source\Run.config
                    }

                    (Get-Content C:\$TestDir\source\Run.config).replace('key="SkipCertificateValidation" value=""', 'key="SkipCertificateValidation" value="True"') | Set-Content C:\$TestDir\source\Run.config
                    (Get-Content C:\$TestDir\source\Run.config).replace('key="SkipCertificateValidation" value="False"', 'key="SkipCertificateValidation" value="True"') | Set-Content C:\$TestDir\source\Run.config

                    #Build & Run tests
                    Write-EventLog -LogName Application -Source "$Using:EventLogSource" -EntryType Information -EventId 0 -Message "Beginning tests build and run."
                    &C:\$TestDir\scripts\run.ps1 -f -b -ErrorAction SilentlyContinue

                    # Copy test result to remote desktop gateway server
                    Write-EventLog -LogName Application -Source "$Using:EventLogSource" -EntryType Information -EventId 0 -Message "About to create directory \\$Using:RDSName\\C$\TestResults\"
                    New-Item -ItemType directory -Path "\\$Using:RDSName\\C$\TestResults\" -Force
                    Write-EventLog -LogName Application -Source "$Using:EventLogSource" -EntryType Information -EventId 0 -Message "Created directory, about to copy C:\$TestDir\testResults\*.html to \$Using:RDSName\\C$\TestResults\"
                    Copy-Item -Path "C:\$TestDir\testResults\*.html" -Destination "\\$Using:RDSName\\C$\TestResults\"

                    Write-EventLog -LogName Application -Source "$Using:EventLogSource" -EntryType Information -EventId 0 -Message "Tests build and run end."
                }
                Catch {
                    Write-EventLog -LogName Application -Source "$Using:EventLogSource" -EntryType Error -EventId 0 -Message  $_
                }
            }
            DependsOn  = '[Package]PISystem', '[cChocoPackageInstaller]visualstudio2017buildtools', '[xPendingReboot]Reboot1'
            PsDscRunAsCredential = $TestRunnerAccount
        }
        #endregion

        

        
    }
}

# SIG # Begin signature block
# MIIpTgYJKoZIhvcNAQcCoIIpPzCCKTsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD9rFV3Fmfsh+2u
# 57Zlvxf84bBI6xE8ZSVWpojwg2PlIqCCDhkwggawMIIEmKADAgECAhAIrUCyYNKc
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
# 3gbIhtAHY4vZjeP6cJwRNpxg12nbe25nQ6vuvIsuJ6eS59QxghqLMIIahwIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA9Tuc6kgdfYBREfbztczrMwDQYJYIZIAWUDBAIBBQCggZ4w
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEBLmJZb/G34IeKRTgjt+pTk8SNmmHry
# ST2opdgka8ifMDIGCisGAQQBgjcCAQwxJDAioSCAHmh0dHA6Ly90ZWNoc3VwcG9y
# dC5vc2lzb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAgCtZQ+Bor6Sq4WtFRfP3piF
# slBcGy5PNDSzJovE3R2Orh2Fsdf5vp+rrKQeEUeZJVBctzrnkoM5SmIDb4Uli3IG
# MJtVKbChdVySHwWeGzBT3LAm+K1/SMhCYza6RFI2Riw1es/ghvfV2Y/ILl2YexE/
# UapDfVGb0BQkcMrlp81vupXi0RdLA0ehxveIkj88DQXHz/DtcBGApYi7Nsq4kt4M
# PNIdhKPIqwJmuRcqzM6PH8rp+yPgApfGQUvjH2nB0rZjdZoMEU6OiTSdo4gymgLW
# IFO1MHIaz1Y6ntOUy4zERzszN6/q6DRIxnl6lgZ/xa5jsx3dMo070BbIk3EPGclj
# 1pjXPNkSw6Rj2KtLHFcNXVlXqOzoRks35T3C7I2Aa3gwWxXNOO3V5Fx8sKL3hSa3
# tJSutbtaBRtIZ1HILU7oV5yAfvZq6nMrV63pM2tkhM3U5lFjyayahSi6at/LZ0pM
# kqWiXR67X8RzSe7nhkuZKajVYs4J6wcSVYNwg91FKCrqjZUKeaBp0cQ2RUVDi7R2
# PRlNlDJLoa0R3toLJIhvj58c5cAq9qXTYpqoINnDhwxhk+lgJ/zrB6BlaY1S8MmS
# z9y3u7EaBUv2Mv8CrwdtEc4jBMbf/x+5W9pSk5Lkh8Ryt0lYIE245P++x2Te5GJV
# Uru7pZDLkwGjazbDu81bH6GCFz4wghc6BgorBgEEAYI3AwMBMYIXKjCCFyYGCSqG
# SIb3DQEHAqCCFxcwghcTAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZIhvcNAQkQ
# AQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCBBeTKYmAG2
# cYSRXcrrM6+SQ7gE0uZ3NylqYD7r/Oh67QIRANIziLQ71OrWlnJeXT1mreQYDzIw
# MjIxMDIxMTgyMTAwWqCCEwcwggbAMIIEqKADAgECAhAMTWlyS5T6PCpKPSkHgD1a
# MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNI
# QTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwOTIxMDAwMDAwWhcNMzMxMTIxMjM1
# OTU5WjBGMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJDAiBgNVBAMT
# G0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZIhvcNAQEBBQAD
# ggIPADCCAgoCggIBAM/spSY6xqnya7uNwQ2a26HoFIV0MxomrNAcVR4eNm28klUM
# YfSdCXc9FZYIL2tkpP0GgxbXkZI4HDEClvtysZc6Va8z7GGK6aYo25BjXL2JU+A6
# LYyHQq4mpOS7eHi5ehbhVsbAumRTuyoW51BIu4hpDIjG8b7gL307scpTjUCDHufL
# ckkoHkyAHoVW54Xt8mG8qjoHffarbuVm3eJc9S/tjdRNlYRo44DLannR0hCRRinr
# PibytIzNTLlmyLuqUDgN5YyUXRlav/V7QG5vFqianJVHhoV5PgxeZowaCiS+nKrS
# nLb3T254xCg/oxwPUAY3ugjZNaa1Htp4WB056PhMkRCWfk3h3cKtpX74LRsf7CtG
# GKMZ9jn39cFPcS6JAxGiS7uYv/pP5Hs27wZE5FX/NurlfDHn88JSxOYWe1p+pSVz
# 28BqmSEtY+VZ9U0vkB8nt9KrFOU4ZodRCGv7U0M50GT6Vs/g9ArmFG1keLuY/ZTD
# cyHzL8IuINeBrNPxB9ThvdldS24xlCmL5kGkZZTAWOXlLimQprdhZPrZIGwYUWC6
# poEPCSVT8b876asHDmoHOWIZydaFfxPZjXnPYsXs4Xu5zGcTB5rBeO3GiMiwbjJ5
# xwtZg43G7vUsfHuOy2SJ8bHEuOdTXl9V0n0ZKVkDTvpd6kVzHIR+187i1Dp3AgMB
# AAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYEFGKK
# 3tBh/I8xFO2XC809KpQU31KcMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1l
# U3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZU
# aW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAFWqKhrzRvN4Vzcw
# /HXjT9aFI/H8+ZU5myXm93KKmMN31GT8Ffs2wklRLHiIY1UJRjkA/GnUypsp+6M/
# wMkAmxMdsJiJ3HjyzXyFzVOdr2LiYWajFCpFh0qYQitQ/Bu1nggwCfrkLdcJiXn5
# CeaIzn0buGqim8FTYAnoo7id160fHLjsmEHw9g6A++T/350Qp+sAul9Kjxo6UrTq
# vwlJFTU2WZoPVNKyG39+XgmtdlSKdG3K0gVnK3br/5iyJpU4GYhEFOUKWaJr5yI+
# RCHSPxzAm+18SLLYkgyRTzxmlK9dAlPrnuKe5NMfhgFknADC6Vp0dQ094XmIvxwB
# l8kZI4DXNlpflhaxYwzGRkA7zl011Fk+Q5oYrsPJy8P7mxNfarXH4PMFw1nfJ2Ir
# 3kHJU7n/NBBn9iYymHv+XEKUgZSCnawKi8ZLFUrTmJBFYDOA4CPe+AOk9kVH5c64
# A0JH6EE2cXet/aLol3ROLtoeHYxayB6a1cLwxiKoT5u92ByaUcQvmvZfpyeXupYu
# hVfAYOd4Vn9q78KVmksRAsiCnMkaBXy6cbVOepls9Oie1FqYyJ+/jbsYXEP10Cro
# 4mLueATbvdH7WwqocH7wl4R44wgDXUcsY6glOJcB0j862uXl9uab3H4szP8XTE0A
# otjWAQ64i+7m4HJViSwnGWH2dwGMMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0o
# ZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhE
# aWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIy
# MjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# OzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGlt
# ZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1
# BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3z
# nIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZ
# Kz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald6
# 8Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zk
# psUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYn
# LvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIq
# x5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOd
# OqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJ
# TYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJR
# k8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEo
# AA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8G
# A1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjAT
# BgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGG
# GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2Nh
# Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYD
# VR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9
# bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0T
# zzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYS
# lm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaq
# T5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl
# 2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1y
# r8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05
# et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6um
# AU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSwe
# Jywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr
# 7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYC
# JtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzga
# oSv27dZ8/DCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcN
# AQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJl
# ZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjEL
# MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
# LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBp
# M+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR
# 0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0
# O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53
# yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4
# x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3Vd
# eGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1C
# doeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJh
# besz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz
# 0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNB
# ERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+
# CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8w
# HQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0
# ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGsw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcw
# AoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElE
# Um9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYE
# VR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqs
# oYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPI
# TtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZ
# qPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/v
# oVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+
# cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDGCA3YwggNy
# AgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTsw
# OQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQQIQDE1pckuU+jwqSj0pB4A9WjANBglghkgBZQMEAgEFAKCB0TAa
# BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTIyMTAy
# MTE4MjEwMFowKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQU84ciTYYzgpI1qZS8vY+W
# 6f4cfHMwLwYJKoZIhvcNAQkEMSIEIOIzwN/fhtDPi7pXaJV0bmIIRzGhasjlnAdw
# LVMSr1Z2MDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIMf04b4yKIkgq+ImOr4axPxP
# 5ngcLWTQTIB1V6Ajtbb6MA0GCSqGSIb3DQEBAQUABIICALfpliCBvF/EHgVCbnV1
# kPtnDs/nIfZ5J5rdIjrng85jKr4laVJ0Sp/1j6tCtNNBcyrp/Ssm40naDeLngOl6
# m9fhg8fPp5uqfcIDuEeOq32NUFeSY1JPdVvA3jiqa9uQhglqRbmNi/MA7JzeWwNd
# 0U7AjnybKhiHynVGWMs0SzJ9tcNx5mtt2RL/nO42WIfbT7hSn2NZNYoUpYQcJkpS
# v+RFpTF9L572wBp9FPJablKz2x8wgDfR18buhywBI3b0EJSBceQQCOqHXMbBMdmK
# ue7OkRLbNJ7/FqfBkqZ0eIfsb96VfxlrDkm7HWIy6JtB5KjKdSUe4vWbTbKpqxUX
# /Eh87OPV/EsevJg8VRgCOHyoNYYWlr8mUg4y3OizxKl0xBF042MYRj6sZ5pkfVGu
# KPfWsJu2uc7yFTzAkL/QGfqYMcOaOA2M+LztAAhIQKVe6GXljBSP0sSdxv1xT8Lo
# H5Wtaz8R+/YKF5F5epLZYxu5kHPguhS7dkEWFL8hAgrMWe2G18uebfCSQesGnb4Z
# +vZn0UUEWtQENpOukYhWRvHP5zvr6fooCC6k7LWtNB1tuzqkfQMb4nmyD66FW+8o
# MlEyZ0LOlL/vkrrT3qD9GOn0Mren8Fz1MkYqOgZsfo7tVOS6LCQSsE5IOpiu4zyI
# DcAEBW8em0f5+UC3OT6w1kqq
# SIG # End signature block
