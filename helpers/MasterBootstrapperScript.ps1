[CmdletBinding(DefaultParametersetname="AutoCreds")]
param(
    $PIVisionPath = 'D:\AVEVA-PI-Vision_2022_.exe',
    $PIPath = 'D:\AVEVA-PI-Server_2018-SP3-Patch-4_.exe',
    $PIProductID = '4b23fd33-f306-44f5-9bf5-28024385023e',
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
        Set-AzStorageBlobContent -File $x.fullname -Container $StorageContainer.Name -Blob $targetPath -Context $StorageContext -Force:$Force | Out-Null
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
        #Set-AzStorageFileContent -Share $StorageShare -Source $_.FullName -Path $path -Force
        Set-AzStorageFileContent -ShareName $ArtifactStorageAccountFileShareName -Context $storageContext -Source $_.FullName -Path $path -Force
    }
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
        New-AzKeyVault -Name $KeyVault -ResourceGroupName $ResourceGroupName -Location $Location -ErrorAction Stop
    }
    else {
        New-AzKeyVault -Name $vaultName -ResourceGroupName $ResourceGroupName -Location $Location -ErrorAction Stop
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

                $passwordLength = 30
                $nonAlphCh = 10
                Do {
                        #Generate password using .net
                        $password = [System.Web.Security.Membership]::GeneratePassword($PasswordLength, $NonAlphCh)
                    }
                    While ($null -ne (Select-String -InputObject $Password -Pattern "\[+\S*\]+"))
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
New-AzResourceGroupDeployment @masterDeploymentParams -Verbose

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
# MIIpTQYJKoZIhvcNAQcCoIIpPjCCKToCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAtlIwOemjoTugh
# 1w8ym0MGXqokPfjI5Ub2ws0chwYJn6CCDhkwggawMIIEmKADAgECAhAIrUCyYNKc
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBwV+OAnywh7Ui+S5Sfqbpn66d+vCJ+e
# ufKoYV5Qk1cWMDIGCisGAQQBgjcCAQwxJDAioSCAHmh0dHA6Ly90ZWNoc3VwcG9y
# dC5vc2lzb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAgANSDEkNy3/E12kQyKEvbLR
# cZS0TgqC+O4h6xdEtixuGU10CMr1l/NfO5BNnIUJ2nfenidpVWQqHAgG4NDCWp7d
# drlLu0XsZhCh1g2U06TPsjDEZhug6/W+Hv8JD7JT32uy4DlHTcmEDpI2vlyuGSb0
# E+9yQO4PaAYbh3gj1aBFAnloinIwVaTHvn2Kdt/HAGziShDBD4Fdb7eiyTCR1RCo
# QxBE/vN8oof5kIglkWb7F42z7ylb1Dvc9X5cXP1T9I0+kC921nAJj+BtRR7bdIMr
# Jx3xcwAxkAxYDCyZeyHpFDhsKihuIpsH6eCBCf0s83MO9MnJJM85rUuc3tSuuIzO
# KEW31L3u/woTBgXAYzbX4X8AID+adquQsXeV/9Qeeh12Fqh9hnku8oA9i1PdLZkp
# +oYNE6YeMHpXH0lIDYbfgzkuuXAy0UAEAoYWTQvj2PlILo2WaHRgUXwtQoYE+GaP
# CeLqjNxGtnzBOkBTMYcvdrqO5D/0V1+1JsdRP5iCzgLgi+6Pnt8qf7Ofu9cS4pTC
# utOix8+tgYieRO9S3XxDmXw3kehudfIiQjt62d/4NsgH4S6OxRnix0PXh3VidqhW
# ZbRLYeyWdGRbkNMadFF+VRq60a1Q4VfAT1qicDVp2aMJdsPyA/vmaZAkDcdMZVtS
# gUsTxxdMIdSY8336srq2BqGCFz0wghc5BgorBgEEAYI3AwMBMYIXKTCCFyUGCSqG
# SIb3DQEHAqCCFxYwghcSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQ
# AQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCCeSAGFRnBt
# NeLzv5Y00lcPeK+i+EBhdWYK0F7cYUI6dQIQaVN2yRYUmRiBkV2rVAInVBgPMjAy
# MjEwMjExODIwNTdaoIITBzCCBsAwggSooAMCAQICEAxNaXJLlPo8Kko9KQeAPVow
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
# MTgyMDU3WjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBTzhyJNhjOCkjWplLy9j5bp
# /hx8czAvBgkqhkiG9w0BCQQxIgQg+2AjZiAiCC/DJYykvh+IfsWcS8uu8N1kMSoe
# shFYVcMwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgx/ThvjIoiSCr4iY6vhrE/E/m
# eBwtZNBMgHVXoCO1tvowDQYJKoZIhvcNAQEBBQAEggIAPn5txnYkJ3TPYOEsrCKX
# Y4MdGF1Ogtib+Jufkaxxhf9mNtFlV+mgtHGvKiHpgdYXOki/0jqRYiHpLJ5ege9l
# WyCPUR+bOPUUipRodXvvnfxCxHygHwDBWAdZDPS5o+GBJpKl3QfljZ1bwqwngNmm
# S1ol2FhPKyoPneXAmQygWUiaTOOhhZXL/MoePlA+bZs8qEnSn1MtZXLhd91YkayL
# FfW5D1DFoBqlTmOCioQNW7prY6dR6NaLjqdSOwVAxC13HBn7h5pI3Bs6h3Gi5Ift
# eWwe45ox5a630I43KL8QnDm6uWlq8l1ddZKSSEgNTZ8zoRVykqRcKyIo2LW6CTwm
# Yc4ZwvPfGfjavKBXaNZ/fpgAgC3ZqVBJAYHC7DcL5MbJK9PJgVKsp7WIt1yxS4MM
# QBJrVPkiseeg302MWzGkpqWph4ojMstH7NSwNJcfs7V+2asRRWUzgXw6L31fShlw
# Z9ag7zlohnclo5cbkQHwIDZS7rdJLkYKd/BEbIleJG9U86FS53WpidCiFW3uCy9C
# XBsevhkygBOd5L8bUVNXMSHqQpBgqtQLammQBJxgyz0RvKLuUoUTpERhrwIGKaVs
# Pio4hqyV4ibWV8Rhkt4fU2J64SRQAORTE0claFMIMJAnuNQIV+bgW9b54MlmV+Q/
# MhFTawI0BUmC6IAalZZChDw=
# SIG # End signature block
