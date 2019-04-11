# Load Azure PowerShell.
$env:PSModulePath = $env:PSModulePath + ";C:\Modules\azurerm_6.7.0"
Import-Module -Name AzureRm -RequiredVersion 6.7.0 -Verbose

# Login into Azure.
$key = ConvertTo-SecureString $env:AZURE_KEY -AsPlainText -Force
$cred = New-Object `
    System.Management.Automation.PSCredential($env:AZURE_APP_ID, $key)
Add-AzureRmAccount -Credential $cred -Tenant $env:AZURE_TENANT
Select-AzureRmSubscription -SubscriptionId $env:AZURE_SUBSCRIPTION_ID
