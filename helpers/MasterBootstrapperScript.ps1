[CmdletBinding(DefaultParametersetname="AutoCreds")]
param(
    $PIVisionPath = 'D:\PI-Vision_2020_.exe',
    $PIPath = 'D:\PI-Server_2018-SP3-Patch-3_.exe',
    $PIProductID = '63819281-e1d6-4c55-b797-b4d1ca9af535',
    $TestFileName = 'PI-System-Deployment-Tests.zip',
    
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
        Set-AzureStorageBlobContent -File $x.fullname -Container $StorageContainer.Name -Blob $targetPath -Context $StorageContext -Force:$Force | Out-Null
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
        Set-AzureStorageFileContent -Share $StorageShare -Source $_.FullName -Path $path -Force
    }
}

if (-not $SkipConnect)
{
    # Make connection to Azure
    $azureAccount = Connect-AzureRmAccount
    Select-AzureRmSubscription -SubscriptionName $SubscriptionName
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
    $artifactResourceGroup = Get-AzureRmResourceGroup -Name $ArtifactResourceGroupName -ErrorAction Stop
}
catch
{
    $artifactResourceGroup = New-AzureRmResourceGroup -Name $ArtifactResourceGroupName -Location $Location
}

# Check if specified Artifact Storage Account exists, if not, create it and assign some permissions
try
{
    $artifactStorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ArtifactResourceGroupName -Name $ArtifactStorageAccountName -ErrorAction Stop
}
catch
{
    $artifactStorageAccount = New-AzureRmStorageAccount -ResourceGroupName $ArtifactResourceGroupName -Name $ArtifactStorageAccountName -SkuName $ArtifactStorageAccountSku -Location $Location -Kind $ArtifactStorageAccountKind
}

# Get Context for the created storage account so we can upload files to it
try
{
    $storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $ArtifactResourceGroupName -Name $ArtifactStorageAccountName).Value[0]
    $storageContext = New-AzureStorageContext -StorageAccountName $ArtifactStorageAccountName -StorageAccountKey $storageAccountKey -ErrorAction Stop
}
catch
{
    Write-Error 'Could not get Azure Storage Context'
    throw
}

# Check if specified Artifact Storage Container exists, otherwise create it
try
{
    $artifactStorageContainer = Get-AzureRmStorageContainer -Name $ArtifactStorageAccountContainerName -ResourceGroupName $ArtifactResourceGroupName -StorageAccountName $ArtifactStorageAccountName -ErrorAction Stop
}
catch
{
    $artifactStorageContainer = New-AzureRmStorageContainer -Name $ArtifactStorageAccountContainerName -ResourceGroupName $ArtifactResourceGroupName -StorageAccountName $ArtifactStorageAccountName -ErrorAction Stop
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
    $artifactStorageAccountFileShare = Get-AzureStorageShare -Name $ArtifactStorageAccountFileShareName -Context $storageContext -ErrorAction Stop
}
catch
{
    $artifactStorageAccountFileShare = New-AzureStorageShare -Name $ArtifactStorageAccountFileShareName -Context $storageContext
}

if ($artifactStorageAccountFileShare -and -not $skipLocalPIArtifact)
{
    Copy-LocalDirectoryToFileShare -SourceFileRoot $LocalArtifactFilePath -StorageContext $storageContext -StorageShare $artifactStorageAccountFileShare
}

# Check if specified resource group to deploy exists, if not, create it
try
{
    $resourceGroup = Get-AzureRmResourceGroup -Name $ResourceGroupName -ErrorAction Stop
}
catch
{
    $resourceGroup = New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location
}

# Get SAS Token to pass to deployment so deployment process has access to file in blob storage
$sasTokenDurationHours = 6
$artifactRoot = "https://$ArtifactStorageAccountName.blob.core.windows.net/$ArtifactStorageAccountContainerName"
$sasToken = New-AzureStorageContainerSASToken -Name $ArtifactStorageAccountContainerName -Context $storageContext -Permission 'r' -ExpiryTime (Get-Date).AddHours($sasTokenDurationHours) | ConvertTo-SecureString -AsPlainText -Force

# Create the Azure key vault to store all deployment creds
try {
    if($ManualCreds) {
        New-AzureRmKeyVault -Name $KeyVault -ResourceGroupName $ResourceGroupName -Location $Location -ErrorAction Stop
    }
    else {
        New-AzureRmKeyVault -Name $vaultName -ResourceGroupName $ResourceGroupName -Location $Location -ErrorAction Stop
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
                $secretValue = Get-AzureKeyVaultSecret -VaultName $vaultName -Name $AdminCredential.UserName -ErrorAction SilentlyContinue
                if (!$secretValue) {-ErrorAction Stop}
            }
            catch {
                Set-AzureKeyVaultSecret -VaultName $vaultName -Name $AdminCredential.UserName -SecretValue ($AdminCredential.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force)
            }
        }
        if ($null -eq $AfCredential) {
            $AfCredential = (Get-Credential -Message "Enter PI Asset Framework service account credentials (exclude domain)")
            try {
                $secretValue = Get-AzureKeyVaultSecret -VaultName $vaultName -Name $AfCredential.UserName -ErrorAction SilentlyContinue
                if (!$secretValue) {-ErrorAction Stop}
            }
            catch {
                Set-AzureKeyVaultSecret -VaultName $vaultName -Name $AfCredential.UserName -SecretValue ($AfCredential.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force)
            }
        }
        if ($null -eq $AnCredential) {
            $AnCredential = (Get-Credential -Message "Enter PI Analysis service account credentials (exclude domain)")
            try {
                $secretValue = Get-AzureKeyVaultSecret -VaultName $vaultName -Name $AnCredential.UserName -ErrorAction SilentlyContinue
                if (!$secretValue) {-ErrorAction Stop}
            }
            catch {
                Set-AzureKeyVaultSecret -VaultName $vaultName -Name $AnCredential.UserName -SecretValue ($AnCredential.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force)
            }
        }
        if ($null -eq $VsCredential) {
            $VsCredential = (Get-Credential -Message "Enter PI Web API service account credentials (used for PI Vision; exclude domain)")
            try {
                $secretValue = Get-AzureKeyVaultSecret -VaultName $vaultName -Name $VsCredential.UserName -ErrorAction SilentlyContinue
                if (!$secretValue) {-ErrorAction Stop}
            }
            catch {
                Set-AzureKeyVaultSecret -VaultName $vaultName -Name $VsCredential.UserName -SecretValue ($VsCredential.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force)
            }
        }
        if ($null -eq $SqlCredential) {
            $SqlCredential = (Get-Credential -Message "Enter SQL Sever service account credentials (exclude domain)")
            try {
                $secretValue = Get-AzureKeyVaultSecret -VaultName $vaultName -Name $SqlCredential.UserName -ErrorAction SilentlyContinue
                if (!$secretValue) {-ErrorAction Stop}
            }
            catch {
                Set-AzureKeyVaultSecret -VaultName $vaultName -Name $SqlCredential.UserName -SecretValue ($SqlCredential.GetNetworkCredential().Password | ConvertTo-SecureString -AsPlainText -Force)
            }
        }
    }

    Else {
        ForEach ($vaultCredential in $vaultCredentials)
        {

            try
            {
                $secretValue = Get-AzureKeyVaultSecret -VaultName $vaultName -Name $vaultCredential
                if (!$secretValue) {-ErrorAction Stop}
                Write-Output "$vaultCredential already exists in $vaultName"

            }
            catch
            {

                $passwordLength = 30
                $nonAlphCh = 10
                Do {
                        #Generate password using .net
                        $password = [System.Web.Security.Membership]::GeneratePassword($PasswordLength, $NonAlphCh)
                    }
                    While ($null -ne (Select-String -InputObject $Password -Pattern "\[+\S*\]+"))
                $secretValue = ConvertTo-SecureString -String $password -AsPlainText -Force
                Set-AzureKeyVaultSecret -VaultName $vaultName -Name $vaultCredential -SecretValue $secretValue
            }
        }

        $AdminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $adminUser, (Get-AzureKeyVaultSecret -VaultName $vaultName -Name $adminUser).SecretValue
        $AfCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $afServiceAccountName, (Get-AzureKeyVaultSecret -VaultName $vaultName -Name $afServiceAccountName).SecretValue
        $AnCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $anServiceAccountName, (Get-AzureKeyVaultSecret -VaultName $vaultName -Name $anServiceAccountName).SecretValue
        $VsCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $vsServiceAccountName, (Get-AzureKeyVaultSecret -VaultName $vaultName -Name $vsServiceAccountName).SecretValue
        $SqlCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $sqlServiceAccountName, (Get-AzureKeyVaultSecret -VaultName $vaultName -Name $sqlServiceAccountName).SecretValue

    }


<#
# Call DEPLOY.master.template.json
$DeploymentParams = @{
    ResourceGroupName = $ResourceGroupName
    TemplateFile = (Join-Path $PSScriptRoot '..\nested\core\DEPLOY.core.template.json')
    namePrefix = $VMNamePrefix
    adminUsername = $AdminCredential.UserName
    adminPassword = $AdminCredential.Password
    deploymentStorageAccountKey = ($storageAccountKey | ConvertTo-SecureString -AsPlainText -Force)
    deploymentStorageAccountName = ($ArtifactStorageAccountName | ConvertTo-SecureString -AsPlainText -Force)
    deploymentStorageAccountFileShareName = ($ArtifactStorageAccountFileShareName | ConvertTo-SecureString -AsPlainText -Force)
    _artifactRoot = $artifactRoot
    _artifactSasToken = $sasToken

}

Write-Output -Message "Deploying the core using DEPLOY.core.template.json"
New-AzureRmResourceGroupDeployment @DeploymentParams


# Call Backend Deployment
$backendDeploymentParams = @{
    ResourceGroupName = $ResourceGroupName
    TemplateFile = (Join-Path $PSScriptRoot '..\nested\backend\DEPLOY.backend.template.json')
    namePrefix = $VMNamePrefix
    adminUsername = $AdminCredential.UserName
    adminPassword = $AdminCredential.Password
    afServiceAccountUsername = $AfCredential.UserName
    afServiceAccountPassword = $AfCredential.Password
    anServiceAccountUsername = $AnCredential.UserName
    anServiceAccountPassword = $AnCredential.Password
    deploymentStorageAccountKey = ($storageAccountKey | ConvertTo-SecureString -AsPlainText -Force)
    deploymentStorageAccountName = ($ArtifactStorageAccountName | ConvertTo-SecureString -AsPlainText -Force)
    deploymentStorageAccountFileShareName = ($ArtifactStorageAccountFileShareName | ConvertTo-SecureString -AsPlainText -Force)
    _artifactRoot = $artifactRoot
    _artifactSasToken = $sasToken
}

Write-Output -Message "Deploying the backend using DEPLOY.backend.template.json"
New-AzureRmResourceGroupDeployment @backendDeploymentParams

# Call Frontend Deployment
$backendDeploymentParams = @{
    ResourceGroupName = $ResourceGroupName
    TemplateFile = (Join-Path $PSScriptRoot '..\nested\frontend\DEPLOY.frontend.template.json')
    namePrefix = $VMNamePrefix
    adminUsername = $AdminCredential.UserName
    adminPassword = $AdminCredential.Password
    vsServiceAccountUsername = $VsCredential.UserName
    vsServiceAccountPassword = $VsCredential.Password
    deploymentStorageAccountKey = ($storageAccountKey | ConvertTo-SecureString -AsPlainText -Force)
    deploymentStorageAccountName = ($ArtifactStorageAccountName | ConvertTo-SecureString -AsPlainText -Force)
    deploymentStorageAccountFileShareName = ($ArtifactStorageAccountFileShareName | ConvertTo-SecureString -AsPlainText -Force)
    _artifactRoot = $artifactRoot
    _artifactSasToken = $sasToken
}

Write-Output -Message "Deploying the backend using DEPLOY.backend.template.json"
New-AzureRmResourceGroupDeployment @backendDeploymentParams

#>

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
New-AzureRmResourceGroupDeployment @masterDeploymentParams -Verbose

<#
$loadbalancerDeploymentParams = @{
    ResourceGroupName = $ResourceGroupName
    TemplateFile = (Join-Path $PSScriptRoot '..\nested\base\base.loadbalancer.template.json')
    namePrefix = $VMNamePrefix
    lbType = 'rds'
    lbName = 'testrdslb'
    subnetReference = '/subscriptions/3426c00d-8af9-49c0-b965-8690115f3526/resourceGroups/alex-master-test2/providers/Microsoft.Network/virtualNetworks/ds-vnet0/subnets/Public'
}
Write-Output -Message "Deploying test lb"
New-AzureRmResourceGroupDeployment @loadbalancerDeploymentParams -Verbose
#>

# SIG # Begin signature block
# MIIcVgYJKoZIhvcNAQcCoIIcRzCCHEMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDHaOCk5CqOV6xP
# VnkWJziJwYqhe/0w0BhzspFDLwjopqCCCo0wggUwMIIEGKADAgECAhAECRgbX9W7
# ZnVTQ7VvlVAIMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xMzEwMjIxMjAwMDBa
# Fw0yODEwMjIxMjAwMDBaMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lD
# ZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQD407Mcfw4Rr2d3B9MLMUkZz9D7RZmxOttE9X/l
# qJ3bMtdx6nadBS63j/qSQ8Cl+YnUNxnXtqrwnIal2CWsDnkoOn7p0WfTxvspJ8fT
# eyOU5JEjlpB3gvmhhCNmElQzUHSxKCa7JGnCwlLyFGeKiUXULaGj6YgsIJWuHEqH
# CN8M9eJNYBi+qsSyrnAxZjNxPqxwoqvOf+l8y5Kh5TsxHM/q8grkV7tKtel05iv+
# bMt+dDk2DZDv5LVOpKnqagqrhPOsZ061xPeM0SAlI+sIZD5SlsHyDxL0xY4PwaLo
# LFH3c7y9hbFig3NBggfkOItqcyDQD2RzPJ6fpjOp/RnfJZPRAgMBAAGjggHNMIIB
# yTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAK
# BggrBgEFBQcDAzB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0fBHow
# eDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBPBgNVHSAESDBGMDgGCmCGSAGG/WwA
# AgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAK
# BghghkgBhv1sAzAdBgNVHQ4EFgQUWsS5eyoKo6XqcQPAYPkt9mV1DlgwHwYDVR0j
# BBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDQYJKoZIhvcNAQELBQADggEBAD7s
# DVoks/Mi0RXILHwlKXaoHV0cLToaxO8wYdd+C2D9wz0PxK+L/e8q3yBVN7Dh9tGS
# dQ9RtG6ljlriXiSBThCk7j9xjmMOE0ut119EefM2FAaK95xGTlz/kLEbBw6RFfu6
# r7VRwo0kriTGxycqoSkoGjpxKAI8LpGjwCUR4pwUR6F6aGivm6dcIFzZcbEMj7uo
# +MUSaJ/PQMtARKUT8OZkDCUIQjKyNookAv4vcn4c10lFluhZHen6dGRrsutmQ9qz
# sIzV6Q3d9gEgzpkxYz0IGhizgZtPxpMQBvwHgfqL2vmCSfdibqFT+hKUGIUukpHq
# aGxEMrJmoecYpJpkUe8wggVVMIIEPaADAgECAhAGVvq6kseGimsYGJGsdvpbMA0G
# CSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0
# IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EwHhcNMjAwNjE2MDAwMDAw
# WhcNMjIwNzIyMTIwMDAwWjCBkTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRQw
# EgYDVQQHEwtTYW4gTGVhbmRybzEVMBMGA1UEChMMT1NJc29mdCwgTExDMQwwCgYD
# VQQLEwNEZXYxFTATBgNVBAMTDE9TSXNvZnQsIExMQzEjMCEGCSqGSIb3DQEJARYU
# cGRlcmVnaWxAb3Npc29mdC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQDPSOGDHDmQTrdWSTB6jfvZ3+ngv2HwU/64ZUGKq+PbyQKcqeRI5MT2Fokj
# K9yp6JoVnipZaBZdjLRj//FuqDR/pNy3VZo1xmufKICqrSS6x2AxKb9l/6mcO/MF
# E2FgG0tND/xftCQlChB91GokCyiVNkwbLleB9uM6yn73ZZkiA0Chmjguipfal+hS
# 27vds5xYGLtcnqWcKcZR5pr838vDT+8zzrxoWQ8se3H9LHYLyCiwk+84mA1M//BW
# xaA7ERt1eJ3vLzYu3+ryH+GFiYEhJHu3FZjktEg5oZ25Vj7iwgTG+/CIMZsEDe5G
# SFvePn3jpMmEaPbOPfx8FVwh8XItAgMBAAGjggHFMIIBwTAfBgNVHSMEGDAWgBRa
# xLl7KgqjpepxA8Bg+S32ZXUOWDAdBgNVHQ4EFgQUmzSViihexjjLsHHW6j+r7Fxw
# U/gwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGA1UdHwRw
# MG4wNaAzoDGGL2h0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQt
# Y3MtZzEuY3JsMDWgM6Axhi9odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vc2hhMi1h
# c3N1cmVkLWNzLWcxLmNybDBMBgNVHSAERTBDMDcGCWCGSAGG/WwDATAqMCgGCCsG
# AQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAEEATCB
# hAYIKwYBBQUHAQEEeDB2MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wTgYIKwYBBQUHMAKGQmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFNIQTJBc3N1cmVkSURDb2RlU2lnbmluZ0NBLmNydDAMBgNVHRMBAf8E
# AjAAMA0GCSqGSIb3DQEBCwUAA4IBAQAR/2LHTPvx/fBATBS0jBBhPEhlrpNgkWZ9
# NCo0wJC5H2V2CpokuZxA4HoK0YCsz2x68BpCnBOX3pdSWC+kQOvLyJayTQew+c/R
# sebGEVp9NNtsnpcFhjM3e7hqsQAm6rCIJWk0Q1sSyYnhnqHA/iS1DxNqZ/qZHx1k
# ise1+9bOefqB1YN+vtmPBlLkboKCklbrJmHSEn4cZNBHjq1yVYOPacuws+8kAEMh
# lDjG2NkfyqF72Jo90SFK7xgjE6euLbvmjGYRSF9h4V+aR6MaEcDkUe2aoCgCmnDX
# Q+9sIKX0AojqBVLFUNQpzelOdjGWNzdcMMSu8p0pNw4xeAbuCEHfMYIRHzCCERsC
# AQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBB
# c3N1cmVkIElEIENvZGUgU2lnbmluZyBDQQIQBlb6upLHhoprGBiRrHb6WzANBglg
# hkgBZQMEAgEFAKCBnjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgVtc8ryX2ZD1p
# I18eqO6VeumOi2kBXWZ81lnVZTYy57AwMgYKKwYBBAGCNwIBDDEkMCKhIIAeaHR0
# cDovL3RlY2hzdXBwb3J0Lm9zaXNvZnQuY29tMA0GCSqGSIb3DQEBAQUABIIBAFnY
# gfF4UTfSpQpWn+0Ik4o3yptQWlBRzr9fu80EHubOBIQnfF1pomlGKdVueonp1Vnu
# HQWFze9INxuhA83YDG9A++XeDQw0+SGI+FzML4TNdl0N4WLzPRckugtF/rQv7Ext
# zmk7AXWx7IqqhwL4wlfskeUHoPQgmFnyBXzdQ1uhARRmmngRRpXt6MSxPeu1Ww7r
# q3Uzs/yivNG0h8GkceKZRYWgdoorXII8ks1tieJ+vq+ESncZ3CPtIKhQ2KZtnU4/
# tVCaoJG24oqBQkWr2XkWS5cmf87dotDD4yqM6NAnLQidgawXiBB92UoPc8ZhqTGv
# WKGwnDuMrrUJNdY5ZK+hgg7IMIIOxAYKKwYBBAGCNwMDATGCDrQwgg6wBgkqhkiG
# 9w0BBwKggg6hMIIOnQIBAzEPMA0GCWCGSAFlAwQCAQUAMHcGCyqGSIb3DQEJEAEE
# oGgEZjBkAgEBBglghkgBhv1sBwEwMTANBglghkgBZQMEAgEFAAQg4HMwbOLRi9zD
# 4XJT3xHD0GaptdbNTFYl41lEkzU6knYCEGATBa1Y0WfzAiZKySvPipwYDzIwMjAx
# MTI0MjE0OTQ2WqCCC7swggaCMIIFaqADAgECAhAEzT+FaK52xhuw/nFgzKdtMA0G
# CSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0
# IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0EwHhcNMTkxMDAxMDAwMDAw
# WhcNMzAxMDE3MDAwMDAwWjBMMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xJDAiBgNVBAMTG1RJTUVTVEFNUC1TSEEyNTYtMjAxOS0xMC0xNTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOlkNZz6qZhlZBvkF9y4KTbM
# ZwlYhU0w4Mn/5Ts8EShQrwcx4l0JGML2iYxpCAQj4HctnRXluOihao7/1K7Sehbv
# +EG1HTl1wc8vp6xFfpRtrAMBmTxiPn56/UWXMbT6t9lCPqdVm99aT1gCqDJpIhO+
# i4Itxpira5u0yfJlEQx0DbLwCJZ0xOiySKKhFKX4+uGJcEQ7je/7pPTDub0ULOsM
# KCclgKsQSxYSYAtpIoxOzcbVsmVZIeB8LBKNcA6Pisrg09ezOXdQ0EIsLnrOnGd6
# OHdUQP9PlQQg1OvIzocUCP4dgN3Q5yt46r8fcMbuQhZTNkWbUxlJYp16ApuVFKMC
# AwEAAaOCAzgwggM0MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMIIBvwYDVR0gBIIBtjCCAbIwggGhBglghkgBhv1s
# BwEwggGSMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BT
# MIIBZAYIKwYBBQUHAgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBmACAAdABo
# AGkAcwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0
# AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAgAEQAaQBn
# AGkAQwBlAHIAdAAgAEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBs
# AHkAaQBuAGcAIABQAGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAgAHcAaABp
# AGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBuAGQAIABh
# AHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBpAG4AIABi
# AHkAIAByAGUAZgBlAHIAZQBuAGMAZQAuMAsGCWCGSAGG/WwDFTAfBgNVHSMEGDAW
# gBT0tuEgHf4prtLkYaWyoiWyyBc1bjAdBgNVHQ4EFgQUVlMPwcYHp03X2G5XcoBQ
# TOTsnsEwcQYDVR0fBGowaDAyoDCgLoYsaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L3NoYTItYXNzdXJlZC10cy5jcmwwMqAwoC6GLGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0
# LmNvbS9zaGEyLWFzc3VyZWQtdHMuY3JsMIGFBggrBgEFBQcBAQR5MHcwJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBPBggrBgEFBQcwAoZDaHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3VyZWRJRFRp
# bWVzdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAQEALoOhRAVKBOO5MlL6
# 2YHwGrv4CY0juT3YkqHmRhxKL256PGNuNxejGr9YI7JDnJSDTjkJsCzox+HizO3L
# eWvO3iMBR+2VVIHggHsSsa8Chqk6c2r++J/BjdEhjOQpgsOKC2AAAp0fR8SftApo
# U39aEKb4Iub4U5IxX9iCgy1tE0Kug8EQTqQk9Eec3g8icndcf0/pOZgrV5JE1+9u
# k9lDxwQzY1E3Vp5HBBHDo1hUIdjijlbXST9X/AqfI1579JSN3Z0au996KqbSRaZV
# DI/2TIryls+JRtwxspGQo18zMGBV9fxrMKyh7eRHTjOeZ2ootU3C7VuXgvjLqQhs
# Uwm09zCCBTEwggQZoAMCAQICEAqhJdbWMht+QeQF2jaXwhUwDQYJKoZIhvcNAQEL
# BQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UE
# CxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJ
# RCBSb290IENBMB4XDTE2MDEwNzEyMDAwMFoXDTMxMDEwNzEyMDAwMFowcjELMAkG
# A1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRp
# Z2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRp
# bWVzdGFtcGluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL3Q
# Mu5LzY9/3am6gpnFOVQoV7YjSsQOB0UzURB90Pl9TWh+57ag9I2ziOSXv2MhkJi/
# E7xX08PhfgjWahQAOPcuHjvuzKb2Mln+X2U/4Jvr40ZHBhpVfgsnfsCi9aDg3iI/
# Dv9+lfvzo7oiPhisEeTwmQNtO4V8CdPuXciaC1TjqAlxa+DPIhAPdc9xck4Krd9A
# Oly3UeGheRTGTSQjMF287DxgaqwvB8z98OpH2YhQXv1mblZhJymJhFHmgudGUP2U
# Kiyn5HU+upgPhH+fMRTWrdXyZMt7HgXQhBlyF/EXBu89zdZN7wZC/aJTKk+FHcQd
# PK/P2qwQ9d2srOlW/5MCAwEAAaOCAc4wggHKMB0GA1UdDgQWBBT0tuEgHf4prtLk
# YaWyoiWyyBc1bjAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzASBgNV
# HRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
# BQcDCDB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0fBHoweDA6oDig
# NoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNybDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNybDBQBgNVHSAESTBHMDgGCmCGSAGG/WwAAgQwKjAo
# BggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzALBglghkgB
# hv1sBwEwDQYJKoZIhvcNAQELBQADggEBAHGVEulRh1Zpze/d2nyqY3qzeM8GN0CE
# 70uEv8rPAwL9xafDDiBCLK938ysfDCFaKrcFNB1qrpn4J6JmvwmqYN92pDqTD/iy
# 0dh8GWLoXoIlHsS6HHssIeLWWywUNUMEaLLbdQLgcseY1jxk5R9IEBhfiThhTWJG
# JIdjjJFSLK8pieV4H9YLFKWA1xJHcLN11ZOFk362kmf7U2GJqPVrlsD0WGkNfMgB
# sbkodbeZY4UijGHKeZR+WfyMD+NvtQEmtmyl7odRIeRYYJu6DC0rbaLEfrvEJStH
# Agh8Sa4TtuF8QkIoxhhWz0E0tmZdtnR79VYzIi8iNrJLokqV2PWmjlIxggJNMIIC
# SQIBATCBhjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEy
# IEFzc3VyZWQgSUQgVGltZXN0YW1waW5nIENBAhAEzT+FaK52xhuw/nFgzKdtMA0G
# CWCGSAFlAwQCAQUAoIGYMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkq
# hkiG9w0BCQUxDxcNMjAxMTI0MjE0OTQ2WjArBgsqhkiG9w0BCRACDDEcMBowGDAW
# BBQDJb1QXtqWMC3CL0+gHkwovig0xTAvBgkqhkiG9w0BCQQxIgQgx+9GaGciS0DG
# TWSQAscyg+1eKJ+2N87dVpAuMBjkbTswDQYJKoZIhvcNAQEBBQAEggEAZ94gzjCL
# M6qftK4VPEZyxh94g/uAOYT7o1P3KHBSl3C5zFeJEZMHT8GtoRhN9tq4YhqcdCay
# H2dtxU/Qii7Sb2va/SYq8X6XnOi9FVnBI0uLOfuFK9rZIsUpZPRXTrTAQ/YVqP/E
# m2C2fvklThemX+/gx+Zssrh7WaaoDGjxcJMchQwkakeSHykGqLzUMIxELZ/CsDJM
# qCW9hVDm7BBg2JiE22rFzCXg3iy7xO0ydgcOmP2+j85ZnL/rqVyLPFPoq9tKsB87
# rXU4HupVMUaCz6i9h/PXPxRTUUhBbPC9DaIJqR3v95Mbj9897iYkMudQZwMRM6ar
# CXEHvc+mLyQL1A==
# SIG # End signature block
