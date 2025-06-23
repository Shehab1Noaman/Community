<#
    .SYNOPSIS
    This script creates a multiline secret in Azure Key Vault from a text file.
    .DESCRIPTION
    This PowerShell script checks for the Az module, installs it if necessary, connects to Azure, and creates a multiline secret in Azure Key Vault from a specified text file.
    .PARAMETER MLSecretName
    The name of the secret to be created in Azure Key Vault.
    .PARAMETER VaultName
    The name of the Azure Key Vault where the secret will be stored.
    .PARAMETER File
    The path to the text file containing the multiline secret.
    .EXAMPLE
    .\CreateMultilineSecret.ps1
    This command runs the script to create a multiline secret in Azure Key Vault.
    .NOTES
    Ensure you have the necessary permissions to create secrets in the specified Key Vault.
    .author
    Shehab Noaman
    .date
    12-06-2025
    .section
    Version
    1.0
    .section
    Requirements
    - PowerShell 5.1 or later
    - Az module installed
    - Access to Azure Key Vault
    .section
    Dependencies
    - Az.Accounts module for Azure authentication
    - Az.KeyVault module for Key Vault operations
    .section
    Change History
    - 1.0: Initial version
    .link
    https://www.modernendpoint.com/managed/Working-with-Azure-Key-Vault-in-PowerShell/
#>


Install-Module -Name Az -AllowClobber -Scope CurrentUser -Force

Connect-AzAccount


# Define secret and vault names
$MLSecretName = "<what you would like the secret Name to be" # expected pattern '^[0-9a-zA-Z-]+$'.
$VaultName = "<your Key Vault Name>" # The name of your Azure Key Vault
# Ensure the Az module is installed and imported

# Define the multiline secret as an array
$SecretArray = @(
    "line1-of-secret",#ClientSecret
    "line2-of-secret", ##TenantID
    "line3-of-secret" #clientId
)
# Note: The secret name must match the expected pattern '^[0-9a-zA-Z-]+$'.
if (-not ($MLSecretName -match '^[0-9a-zA-Z-]+$')) {
    Write-Error "Secret name '$MLSecretName' does not match the expected pattern '^[0-9a-zA-Z-]+$'."
    exit 1
}

# Ensure the Key Vault exists
try {
    Get-AzKeyVault -VaultName $VaultName -ErrorAction Stop
} catch {
    Write-Error "Key Vault '$VaultName' does not exist or you do not have access."
    exit 1
}

# Check if the secret already exists
try {
    $existingSecret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $MLSecretName -ErrorAction Stop
    Write-Host "Secret '$MLSecretName' already exists in Key Vault '$VaultName'."
    exit 0
} catch {
    if ($_.Exception.Message -notlike "*not found*") {
        Write-Error "Failed to check for existing secret: $_"
        exit 1
    }
}
# Combine the array into a single string with line breaks
$SecretImport = $SecretArray -join "`n"

# Optional: Check if the string is null or whitespace
if ([string]::IsNullOrWhiteSpace($SecretImport)) {
    Write-Error "Secret data is empty."
    exit 1
}


# Convert the secret to a secure string
$MLSecretValue = ConvertTo-SecureString -String $SecretImport -AsPlainText -Force

# Set the multiline secret in Key Vault
try {
    Set-AzKeyVaultSecret -VaultName $VaultName -Name $MLSecretName -SecretValue $MLSecretValue -ErrorAction Stop
    Write-Host "Secret '$MLSecretName' successfully set in Key Vault '$VaultName'."
} catch {
    Write-Error "Failed to set secret: $_"
    exit 1
}
## Retrieve and display the secret to verify
# Retrieve the secret to verify it was set correctly
# Note: This will display the secret in plain text, which is not recommended for production use.
#Get-AzKeyVaultSecret -VaultName $VaultName -Name $MLSecretName -AsPlainText
