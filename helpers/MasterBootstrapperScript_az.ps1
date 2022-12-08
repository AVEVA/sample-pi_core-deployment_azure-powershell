[CmdletBinding(DefaultParametersetname="AutoCreds")]
param(
    $PIVisionPath = 'D:\PI-Vision_2020_.exe',
    $PIPath = 'D:\PI-Server_2018-SP3-Patch-3_.exe',
    $PIProductID = '63819281-e1d6-4c55-b797-b4d1ca9af535',
    $TestFileName = 'sample-pi_core-pi_core_deployment_tests-powershell-main.zip',
    
    # Parameters passed from StarterScript ********************************************************************************************
    #Deployment target variables (Azure subscr., Azure geo location (eg., 'WestUS'), Azure resource group)
    [Parameter(Mandatory=$true)]
    $SubscriptionName,
    [Parameter(Mandatory=$true)]
    $Location,
    [Parameter(Mandatory=$true)]
    $ResourceGroupName,
    [Parameter(Mandatory=$true)]
    [string]$deployHA,
    [Parameter(Mandatory=$true)]
    $EnableOSIsoftTelemetry,
    [Parameter(Mandatory=$true)]
    $EnableMicrosoftTelemetry,
    
    #*********************************************************************************************************************************

    [Parameter(ParameterSetName='ManualCreds', Mandatory=$true)]
    $KeyVault,

    # Credential should not include the domain, so just username and password
    # Can define as function params or, if left blank, script will prompt user
    [Parameter(ParameterSetName='ManualCreds')]
    [pscredential]
    $AdminCredential,

    [Parameter(ParameterSetName='ManualCreds')]
    [pscredential]
    $AfCredential,

    [Parameter(ParameterSetName='ManualCreds')]
    [pscredential]
    $AnCredential,

    [Parameter(ParameterSetName='ManualCreds')]
    [pscredential]
    $VsCredential,

    [Parameter(ParameterSetName='ManualCreds')]
    [pscredential]
    $SqlCredential,

    $ArtifactResourceGroupName = $ResourceGroupName,
    $ArtifactStorageAccountName,
    $ArtifactStorageAccountContainerName = 'azureds-artifacts',
    # Azure File share to store other artifacts (installers)
    $ArtifactStorageAccountFileShareName = 'pi2018',

    # Local directory for artifacts
    $LocalArtifactFilePath = (Join-Path $PSScriptRoot '..\LocalArtifacts'),
    #*****************************************************************************************************************
    
    # SKU to use if need to create artifact storage account
    $ArtifactStorageAccountSku = 'Standard_LRS',
    # Kind of storage account to use for artifact storage account
    $ArtifactStorageAccountKind = 'StorageV2',
    # Path to pull Nuget packages for DSC modules (Temporary until can host packages somewhere public)
    $LocalNugetSource = (Join-Path $PSScriptRoot '..\LocalNugetPackages'),

    # Path to nuget executable
    $NugetPath = (Join-Path $PSScriptRoot '..\nuget.exe'),

    $VMNamePrefix = 'ds',
    [Parameter(ParameterSetName='ManualCreds')]
    [switch]
    $ManualCreds,
    # Specify to skip connection if already connected
    [switch]
    $SkipConnect,
    # Specify to skip downloading DSC artifacts
    [switch]
    $skipDscArtifact,
    [switch]
    $skipLocalPIArtifact,
    $DSCName
)

#  Ensure deployHA, EnableMicrosoftTelemetry and EnableOSIsoftTelemetry parameters from starter script are lowercase
$deployHA = $deployHA.ToLower()
$EnableMicrosoftTelemetry = $EnableMicrosoftTelemetry.ToLower()
$EnableOSIsoftTelemetry = $EnableOSIsoftTelemetry.ToLower()

# https://blogs.technet.microsoft.com/389thoughts/2017/12/23/get-uniquestring-generate-unique-id-for-azure-deployments/
function Get-UniqueString ([string]$id, $length=13)
{
    $hashArray = (new-object System.Security.Cryptography.SHA512Managed).ComputeHash($id.ToCharArray())
    -join ($hashArray[1..$length] | ForEach-Object { [char]($_ % 26 + [byte][char]'a') })
}

# "Resource group name"-determined unique string used for creating globally unique Azure resources
$rgString = Get-UniqueString -id $ResourceGroupName -length 5

# Variables used for automatic creation of creds when none are specifed at deployment
[string]$vaultName = ($VMNamePrefix+'-vault-'+$rgString)
[string]$adminUser = ($VMNamePrefix+'-admin')
[string]$afServiceAccountName = ($VMNamePrefix+'-piaf-svc')
[string]$anServiceAccountName = ($VMNamePrefix+'-pian-svc')
[string]$vsServiceAccountName = ($VMNamePrefix+'-pivs-svc')
[string]$sqlServiceAccountName = ($VMNamePrefix+'-sql-svc')
$vaultCredentials = (
    $adminUser,
    $afServiceAccountName,
    $anServiceAccountName,
    $vsServiceAccountName,
    $sqlServiceAccountName
)


# https://stackoverflow.com/questions/38354888/upload-files-and-folder-into-azure-blob-storage
function Copy-LocalDirectoryToBlobStorage
{
    param(
        $SourceFileRoot,
        $StorageContext,
        $StorageContainer
    )
    $sourceRoot = Get-Item $SourceFileRoot
    $filesToUpload = Get-ChildItem $SourceFileRoot -Recurse -File
    # TODO: Make this path manipulation more robust
    foreach ($x in $filesToUpload) {
        $targetPath = $sourceRoot.Name + "/" + ($x.fullname.Substring($sourceRoot.FullName.Length + 1)).Replace("\\", "/")
        Write-Verbose "targetPath: $targetPath"
        Write-Verbose "Uploading $("\" + $x.fullname.Substring($sourceRoot.FullName.Length + 1)) to $($StorageContainer.CloudBlobContainer.Uri.AbsoluteUri + "/" + $targetPath)"
        Set-AzStorageBlobContent -File $x.fullname -Container $StorageContainer.Name -Blob $targetPath -Context $StorageContext -Force
    }
}

function Copy-LocalDirectoryToFileShare
{
    param(
        $SourceFileRoot,
        $StorageShare
    )
    $sourceRoot = Get-Item $SourceFileRoot
    Get-ChildItem -Path $SourceFileRoot -Recurse | Where-Object { $_.GetType().Name -eq "FileInfo"} | ForEach-Object {
        $path=$_.FullName.Substring($sourceRoot.FullName.Length+1).Replace("\","/")
        Set-AzStorageFileContent -ShareName $ArtifactStorageAccountFileShareName -Context $storageContext -Source $_.FullName -Path $path -Force
    }
}

function Get-RandomCharacters($length, $characters) { 
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length } 
    $private:ofs="" 
    return [String]$characters[$random]
}

function Scramble-String([string]$inputString){     
    $characterArray = $inputString.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $outputString = -join $scrambledStringArray
    return $outputString 
}

if (-not $SkipConnect)
{
    # Make connection to Azure
    $azureAccount = Connect-AzAccount
    Select-AzSubscription -Subscription $SubscriptionName
}

# Set default ArtifactStorageAccountName using the Get-UniqueString function
if (-not $ArtifactStorageAccountName) { $ArtifactStorageAccountName = 'osiazureds' + (Get-UniqueString -id $ArtifactResourceGroupName -length 12) }

# Generate Artifact Zip files that are used by DSC
if (-not $skipDscArtifact) {
$dscArtifactPath = (Join-Path $env:temp 'dsc')
$dscArtifactParams = @{
    NugetPath = $NugetPath
    LocalNugetSource = $LocalNugetSource
    OutputDirectory = $dscArtifactPath
}
if ($null -ne $DSCName) {
    $dscArtifactParams.add("DSCName",$DSCName)
}
& (Join-Path $PSScriptRoot 'CreateDSCArtifactZip.ps1') @dscArtifactParams
}

# Check if specified Artifact Resource Group exists, if not, create it
try
{
    $artifactResourceGroup = Get-AzResourceGroup -Name $ArtifactResourceGroupName -ErrorAction Stop
}
catch
{
    $artifactResourceGroup = New-AzResourceGroup -Name $ArtifactResourceGroupName -Location $Location
}

# Check if specified Artifact Storage Account exists, if not, create it and assign some permissions
try
{
    $artifactStorageAccount = Get-AzStorageAccount -ResourceGroupName $ArtifactResourceGroupName -Name $ArtifactStorageAccountName -ErrorAction Stop
}
catch
{
    $artifactStorageAccount = New-AzStorageAccount -ResourceGroupName $ArtifactResourceGroupName -Name $ArtifactStorageAccountName -SkuName $ArtifactStorageAccountSku -Location $Location -Kind $ArtifactStorageAccountKind
}

# Get Context for the created storage account so we can upload files to it
try
{
    $storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $ArtifactResourceGroupName -Name $ArtifactStorageAccountName).Value[0]
    $storageContext = New-AzStorageContext -StorageAccountName $ArtifactStorageAccountName -StorageAccountKey $storageAccountKey -ErrorAction Stop
}
catch
{
    Write-Error 'Could not get Azure Storage Context'
    throw
}

# Check if specified Artifact Storage Container exists, otherwise create it
try
{
    $artifactStorageContainer = Get-AzRmStorageContainer -Name $ArtifactStorageAccountContainerName -ResourceGroupName $ArtifactResourceGroupName -StorageAccountName $ArtifactStorageAccountName -ErrorAction Stop
}
catch
{
    $artifactStorageContainer = New-AzRmStorageContainer -Name $ArtifactStorageAccountContainerName -ResourceGroupName $ArtifactResourceGroupName -StorageAccountName $ArtifactStorageAccountName -ErrorAction Stop
}

# Upload the necessary files to blob storage (ARM Templates, DSC Artifacts, Deployment Scripts)
if ($artifactStorageContainer)
{
    $nestedRoot = (Get-Item (Join-Path $PSScriptRoot '..\nested')).FullName
    $deploymentScriptsRoot = (Get-Item (Join-Path $PSScriptRoot '..\scripts\deployment')).FullName
    Copy-LocalDirectoryToBlobStorage -SourceFileRoot $nestedRoot -StorageContext $storageContext -StorageContainer $artifactStorageContainer
    if (-not $skipDscArtifact) {
    Copy-LocalDirectoryToBlobStorage -SourceFileRoot $dscArtifactPath -StorageContext $storageContext -StorageContainer $artifactStorageContainer
    }
    Copy-LocalDirectoryToBlobStorage -SourceFileRoot $deploymentScriptsRoot -StorageContext $storageContext -StorageContainer $artifactStorageContainer
}

try
{
    $artifactStorageAccountFileShare = Get-AzStorageShare -Name $ArtifactStorageAccountFileShareName -Context $storageContext -ErrorAction Stop
}
catch
{
    $artifactStorageAccountFileShare = New-AzStorageShare -Name $ArtifactStorageAccountFileShareName -Context $storageContext
}

if ($artifactStorageAccountFileShare -and -not $skipLocalPIArtifact)
{
    Copy-LocalDirectoryToFileShare -SourceFileRoot $LocalArtifactFilePath -StorageContext $storageContext -StorageShare $artifactStorageAccountFileShare
}

# Check if specified resource group to deploy exists, if not, create it
try
{
    $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
}
catch
{
    $resourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
}

# Get SAS Token to pass to deployment so deployment process has access to file in blob storage
$sasTokenDurationHours = 6
$artifactRoot = "https://$ArtifactStorageAccountName.blob.core.windows.net/$ArtifactStorageAccountContainerName"
$sasToken = New-AzStorageContainerSASToken -Name $ArtifactStorageAccountContainerName -Context $storageContext -Permission 'r' -ExpiryTime (Get-Date).AddHours($sasTokenDurationHours) | ConvertTo-SecureString -AsPlainText -Force

# Create the Azure key vault to store all deployment creds
try {
    if($ManualCreds) {
        Write-Output -Message "ManualCreds: Create key value"
        New-AzKeyVault -VaultName $KeyVault -ResourceGroupName $ResourceGroupName -Location $Location -SoftDeleteRetentionInDays 7 -ErrorAction Stop
    }
    else {
      Write-Output -Message "Create key value"
      New-AzKeyVault -VaultName $vaultName -ResourceGroupName $ResourceGroupName -Location $Location -SoftDeleteRetentionInDays 7  -ErrorAction Stop
    }
}
catch
{
    Write-Host $_.Exception.Message
}

# If manual creds are used, user is prompted for creds to be used. These creds are also stored in an Azure key vault
if ($ManualCreds) {
    # Prepare variables to be passed
        if ($null -eq $AdminCredential) {
            $AdminCredential = (Get-Credential -Message "Enter domain admin credentials (exclude domain)")
            try {
                $secretValue = Get-AzKeyVaultSecret -VaultName $vaultName -Name $AdminCredential.UserName -ErrorAction SilentlyContinue
                if (!$secretValue) {-ErrorAction Stop}
            }
            catch {
                Set-AzKeyVaultSecret -VaultName $vaultName -Name $AdminCredential.UserName -SecretValue ($AdminCredential.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force)
            }
        }
        if ($null -eq $AfCredential) {
            $AfCredential = (Get-Credential -Message "Enter PI Asset Framework service account credentials (exclude domain)")
            try {
                $secretValue = Get-AzKeyVaultSecret -VaultName $vaultName -Name $AfCredential.UserName -ErrorAction SilentlyContinue
                if (!$secretValue) {-ErrorAction Stop}
            }
            catch {
                Set-AzKeyVaultSecret -VaultName $vaultName -Name $AfCredential.UserName -SecretValue ($AfCredential.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force)
            }
        }
        if ($null -eq $AnCredential) {
            $AnCredential = (Get-Credential -Message "Enter PI Analysis service account credentials (exclude domain)")
            try {
                $secretValue = Get-AzKeyVaultSecret -VaultName $vaultName -Name $AnCredential.UserName -ErrorAction SilentlyContinue
                if (!$secretValue) {-ErrorAction Stop}
            }
            catch {
                Set-AzKeyVaultSecret -VaultName $vaultName -Name $AnCredential.UserName -SecretValue ($AnCredential.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force)
            }
        }
        if ($null -eq $VsCredential) {
            $VsCredential = (Get-Credential -Message "Enter PI Web API service account credentials (used for PI Vision; exclude domain)")
            try {
                $secretValue = Get-AzKeyVaultSecret -VaultName $vaultName -Name $VsCredential.UserName -ErrorAction SilentlyContinue
                if (!$secretValue) {-ErrorAction Stop}
            }
            catch {
                Set-AzKeyVaultSecret -VaultName $vaultName -Name $VsCredential.UserName -SecretValue ($VsCredential.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force)
            }
        }
        if ($null -eq $SqlCredential) {
            $SqlCredential = (Get-Credential -Message "Enter SQL Sever service account credentials (exclude domain)")
            try {
                $secretValue = Get-AzKeyVaultSecret -VaultName $vaultName -Name $SqlCredential.UserName -ErrorAction SilentlyContinue
                if (!$secretValue) {-ErrorAction Stop}
            }
            catch {
                Set-AzKeyVaultSecret -VaultName $vaultName -Name $SqlCredential.UserName -SecretValue ($SqlCredential.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force)
            }
        }
    }

    Else {
        ForEach ($vaultCredential in $vaultCredentials)
        {

            try
            {
                $secretValue = Get-AzKeyVaultSecret -VaultName $vaultName -Name $vaultCredential
                if (!$secretValue) {-ErrorAction Stop}
                Write-Output "$vaultCredential already exists in $vaultName"

            }
            catch
            {
                $password = Get-RandomCharacters -length 15 -characters 'abcdefghiklmnoprstuvwxyz'
                $password += Get-RandomCharacters -length 5 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
                $password += Get-RandomCharacters -length 5 -characters '1234567890'
                $password += Get-RandomCharacters -length 5 -characters '!$#%'
                $password = Scramble-String $password 
                
                $secretValue = ConvertTo-SecureString -String $password -AsPlainText -Force
                Set-AzKeyVaultSecret -VaultName $vaultName -Name $vaultCredential -SecretValue $secretValue
            }
        }

        $AdminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $adminUser, (Get-AzKeyVaultSecret -VaultName $vaultName -Name $adminUser).SecretValue
        $AfCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $afServiceAccountName, (Get-AzKeyVaultSecret -VaultName $vaultName -Name $afServiceAccountName).SecretValue
        $AnCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $anServiceAccountName, (Get-AzKeyVaultSecret -VaultName $vaultName -Name $anServiceAccountName).SecretValue
        $VsCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $vsServiceAccountName, (Get-AzKeyVaultSecret -VaultName $vaultName -Name $vsServiceAccountName).SecretValue
        $SqlCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $sqlServiceAccountName, (Get-AzKeyVaultSecret -VaultName $vaultName -Name $sqlServiceAccountName).SecretValue

    }

# Call Frontend Deployment
$masterDeploymentParams = @{
    ResourceGroupName = $ResourceGroupName
    TemplateFile = (Join-Path $PSScriptRoot '..\nested\base\DEPLOY.master.template.json')
    namePrefix = $VMNamePrefix
    EnableMicrosoftTelemetry = $EnableMicrosoftTelemetry
    EnableOSIsoftTelemetry = $EnableOSIsoftTelemetry
    PIVisionPath = $PIVisionPath
    PIPath = $PIPath
    PIProductID = $PIProductID
    TestFileName = $TestFileName
    deployHA = $deployHA
    adminUsername = $AdminCredential.UserName
    adminPassword = $AdminCredential.Password
    afServiceAccountUsername = $AfCredential.UserName
    afServiceAccountPassword = $AfCredential.Password
    anServiceAccountUsername = $AnCredential.UserName
    anServiceAccountPassword = $AnCredential.Password
    sqlServiceAccountUsername = $SqlCredential.UserName
    sqlServiceAccountPassword = $SqlCredential.Password
    vsServiceAccountUsername = $VsCredential.UserName
    vsServiceAccountPassword = $VsCredential.Password
    deploymentStorageAccountKey = ($storageAccountKey | ConvertTo-SecureString -AsPlainText -Force)
    deploymentStorageAccountName = ($ArtifactStorageAccountName | ConvertTo-SecureString -AsPlainText -Force)
    deploymentStorageAccountFileShareName = ($ArtifactStorageAccountFileShareName | ConvertTo-SecureString -AsPlainText -Force)
    _artifactRoot = $artifactRoot
    _artifactSasToken = $sasToken
}

Write-Output -Message "Deploying the full environment using DEPLOY.master.template.json"
Write-Output -Message $PIVisionPath
Write-Output -Message $PIPath
Write-Output -Message $PIProductID
New-AzResourceGroupDeployment @masterDeploymentParams -Verbose

# SIG # Begin signature block
# MIIpTgYJKoZIhvcNAQcCoIIpPzCCKTsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAB76wUOJmGC9Gs
# f+NhUkyu/Jlg9FBsQLykJR26h1IYEqCCDhkwggawMIIEmKADAgECAhAIrUCyYNKc
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOeV8Imek/F55qgsAXMzu3aLKsfpsugu
# IVe6azurcMZUMDIGCisGAQQBgjcCAQwxJDAioSCAHmh0dHA6Ly90ZWNoc3VwcG9y
# dC5vc2lzb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAgCXCQ8GCdhsFxFkH+6032cp
# ZonNlxrRD6lo42ajyupJr0XR3minQxrkNWtOjXm8kBmbDFWFBFs7e1F2/zHNP6I6
# mi5CcSjY9RDWGGYz7Yu+sHor4CWZSNW6ftUK9xNJ81nr1yeXH8jYnHQ05HB1AKNK
# L1S1epIK4vrybfvyz7AiBpSXNEUIs5VLYwW4oQ8CU87Nrf9ANs3IRj103Fb2sWnn
# gE67jBWzXowaKJzYihJL02lhPA0/O9qWoNjbFRBZRHZhyprUPU1+n9jOzVlYQg+h
# eyCP6KVQi5IODvS+PMrxytuvN51vjGtt7bztmiEgKVDRTO1I5CvEjEfJ5wMJfa4b
# hBcU+ZANff/OQUwyR9h/vkZFON4D9bAyLC1Vz99RUVhH/Pv5vErUrLj7qzHWiGpT
# NgVS6wP8gQuj9pyW8ayTYoy34mvq2Yr5ojETNO+8RX/GGHx1b1yDfmyeqAEY3zSq
# 8mufgaNJ4vOJtwbxczXD/HCsFXBJSGzw1WI7/F1x4AsRqBfDZ0oTrunFHFMkxUZM
# p5DnpPcMqBs2NmnLhjlfH2lK94MQ4qBNda+sAMqeOWOJWv4QrnfkvqPdqjulA03X
# EN4cKyGppCqhGdZiRm0tG9m8RbEIBWe2Hrp5PEwWIZ6wG+cSe5KL2OmQQqqiWouN
# I0l8dEh/INXPDEkdhj5AE6GCFz4wghc6BgorBgEEAYI3AwMBMYIXKjCCFyYGCSqG
# SIb3DQEHAqCCFxcwghcTAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZIhvcNAQkQ
# AQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCCcv0n8arWS
# fJmcF7xGwSHpTdGGwLkNF4Hbwo8GE+/aiQIRALroMjTZBPDc8K/oh+f1Z98YDzIw
# MjIxMDIxMTgyMDU3WqCCEwcwggbAMIIEqKADAgECAhAMTWlyS5T6PCpKPSkHgD1a
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
# MTE4MjA1N1owKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQU84ciTYYzgpI1qZS8vY+W
# 6f4cfHMwLwYJKoZIhvcNAQkEMSIEIEb3j4jwUH+RhEx1BW3diWVUVaBvebM0fteZ
# VZ1iSHZ3MDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIMf04b4yKIkgq+ImOr4axPxP
# 5ngcLWTQTIB1V6Ajtbb6MA0GCSqGSIb3DQEBAQUABIICALqM1RXw3xs2sUd6QriN
# C5DMksSi1dt9Q5jEbA58KMZ5U8+Iw2krDbLFHHoXItHY2B22+y5mSu6o7dSNKXiD
# uQ+BSot7mJnB3r7//3UxVxqGIsG3TQdGm0jFpTyDg036i3ACbVy+F7cz3pOlbUKP
# Cvv+/Df/eeZKpUKnffpXbTNhW1mZAZprI+m5FqZ03TPD8+BL3Pa1BmFoCoY4PWVe
# a3xF4S9BPVIsZDTS9grgOElhUTzL16XR6cGL3kShGFMooY7p9PsZ7zbHdl5ww6fE
# eJTotFc0Vro+npEYrCTDwZqP3hBOSZ3msgA+8m8ZqcOSjM71+kDbsetmogtWv73h
# c8pQYEWNibZ58fZJxjqb2ZrNZFCP0KKwYs2YJOTEjkwkjv2iFbpHkbIKE+jtyjCf
# 2K6OdtIS8+AQwLK5TccISb1vnWzNWbEJKiCsBr8AiNUF94K5mvievDukEwRL9wTj
# UIh3bySf0c/vRDNOX2AbxX4kZLY5RXy/2ayVmyUtNBgpwo5kjOBFXamcD/g3bRDM
# gcfbemqqdgUWofM3Yor+eZ/fX2b2Xdgeai65GA6MBc0b4VzaNV67S+JLPFsCLOlU
# VGlE6UE0EmM3ydvmHmMFMUpuLYHdhT04tt11VfAbGA+XIhXAydUuNLbyezoltZKA
# utazyHBdjuHLU+Gb0WimzBZG
# SIG # End signature block
