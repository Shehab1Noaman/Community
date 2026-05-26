function New-M365BackupCertificate {
    <#
    .SYNOPSIS
        Creates a self-signed certificate for the BackupM365 app registration and
        exports the public-key (.cer) file for upload to Entra ID.

    .DESCRIPTION
        Generates a 2048-bit RSA self-signed certificate, installs it into the
        CurrentUser\My personal store, and exports the public key (.cer) to the
        specified output folder. The private key stays in the user's certificate
        store and is used at runtime by the backup module.

        Run interactively as the admin who will execute the backup.
        After running, use New-M365BackupApp to register the Entra app.

    .PARAMETER Subject
        The certificate subject (CN). Defaults to 'CN=BackupM365'.

    .PARAMETER YearsValid
        How many years until expiry. Defaults to 2.

    .PARAMETER OutputFolder
        Where to write the .cer and .pfx files.
        Defaults to an 'output' folder inside the current working directory.

    .PARAMETER PfxPassword
        SecureString password used to protect the exported .pfx file. If omitted,
        you will be prompted interactively.

    .PARAMETER SkipPfxExport
        Skip exporting the .pfx file (only the public-key .cer is produced).

    .EXAMPLE
        New-M365BackupCertificate

    .EXAMPLE
        New-M365BackupCertificate -Subject 'CN=BackupM365-Prod' -YearsValid 3

    .EXAMPLE
        New-M365BackupCertificate -OutputFolder 'C:\Certs' -SkipPfxExport
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Subject = 'CN=BackupM365',

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$YearsValid = 2,

        [Parameter()]
        [string]$OutputFolder,

        [Parameter()]
        [securestring]$PfxPassword,

        [Parameter()]
        [switch]$SkipPfxExport
    )

    if (-not $OutputFolder) {
        $OutputFolder = Join-Path (Get-Location).Path 'output'
    }

    if (-not (Get-Command -Name New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
        throw 'New-SelfSignedCertificate is not available. This cmdlet requires Windows PowerShell or PowerShell 7 on Windows.'
    }

    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null

    $notAfter = (Get-Date).AddYears($YearsValid)

    Write-Host "Creating self-signed certificate '$Subject' (expires $notAfter)..." -ForegroundColor Cyan

    $cert = New-SelfSignedCertificate `
        -Subject           $Subject `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy   Exportable `
        -KeySpec           Signature `
        -KeyLength         2048 `
        -KeyAlgorithm      RSA `
        -HashAlgorithm     SHA256 `
        -NotAfter          $notAfter `
        -Type              CodeSigningCert

    $safeName    = ($Subject -replace '^CN=','' -replace '[^A-Za-z0-9_-]','_')
    $cerPath     = Join-Path $OutputFolder ("$safeName.cer")
    $pfxPath     = Join-Path $OutputFolder ("$safeName.pfx")
    $summaryPath = Join-Path $OutputFolder ("$safeName.certificate-info.json")

    Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null

    $pfxExported = $false
    if (-not $SkipPfxExport) {
        if (-not $PfxPassword) {
            $PfxPassword = Read-Host -AsSecureString -Prompt "Enter a password to protect the exported .pfx (used when importing on the machine that runs the backup)"
        }

        Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $PfxPassword -Force | Out-Null
        $pfxExported = $true
    }

    $info = [pscustomobject]@{
        Subject               = $cert.Subject
        Thumbprint            = $cert.Thumbprint
        NotBefore             = $cert.NotBefore
        NotAfter              = $cert.NotAfter
        SerialNumber          = $cert.SerialNumber
        StoreLocation         = 'Cert:\CurrentUser\My'
        PublicKeyFile         = $cerPath
        PfxFile               = if ($pfxExported) { $pfxPath } else { $null }
        UploadInstructions    = 'Upload the .cer file in Entra ID portal -> App registrations -> <your app> -> Certificates & secrets -> Certificates -> Upload certificate.'
        ImportInstructions    = if ($pfxExported) {
            "On the machine that will run the backup, import the .pfx into LocalMachine\My (run PowerShell as Administrator):`n" +
            "  `$pwd = Read-Host -AsSecureString -Prompt 'PFX password'`n" +
            "  Import-PfxCertificate -FilePath '$pfxPath' -CertStoreLocation 'Cert:\LocalMachine\My' -Password `$pwd -Exportable`n" +
            "Then verify with: Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -eq '$($cert.Thumbprint)'"
        } else { $null }
    }

    $info | ConvertTo-Json -Depth 5 | Set-Content -Path $summaryPath -Encoding UTF8

    Write-Host ''
    Write-Host '=== Certificate created ===' -ForegroundColor Green
    Write-Host ("Thumbprint  : {0}" -f $cert.Thumbprint)
    Write-Host ("Subject     : {0}" -f $cert.Subject)
    Write-Host ("Expires     : {0}" -f $cert.NotAfter)
    Write-Host ("Public key  : {0}" -f $cerPath)
    if ($pfxExported) {
        Write-Host ("PFX (private): {0}" -f $pfxPath)
    }
    Write-Host ("Info file   : {0}" -f $summaryPath)
    Write-Host ''
    Write-Host 'Next steps:' -ForegroundColor Yellow
    Write-Host '  1. Upload the .cer file to your Entra app:' -ForegroundColor Yellow
    Write-Host ("     {0}" -f $cerPath)
    Write-Host '     Entra ID portal -> App registrations -> <your app> -> Certificates & secrets -> Certificates -> Upload certificate.'
    if ($pfxExported) {
        Write-Host ''
        Write-Host '  2. On the machine that will run the backup, import the .pfx into LocalMachine\My' -ForegroundColor Yellow
        Write-Host '     (open PowerShell as Administrator):'
        Write-Host ''
        Write-Host ("     `$pwd = Read-Host -AsSecureString -Prompt 'PFX password'") -ForegroundColor Gray
        Write-Host ("     Import-PfxCertificate ``") -ForegroundColor Gray
        Write-Host ("         -FilePath '{0}' ``" -f $pfxPath) -ForegroundColor Gray
        Write-Host ("         -CertStoreLocation 'Cert:\LocalMachine\My' ``") -ForegroundColor Gray
        Write-Host ("         -Password `$pwd ``") -ForegroundColor Gray
        Write-Host ("         -Exportable") -ForegroundColor Gray
        Write-Host ''
        Write-Host '     Verify the import:'
        Write-Host ("     Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -eq '{0}'" -f $cert.Thumbprint) -ForegroundColor Gray
        Write-Host ''
        Write-Host ('  3. Then run: New-M365BackupApp -CertificateThumbprint ' + $cert.Thumbprint) -ForegroundColor Yellow
    } else {
        Write-Host ''
        Write-Host ('  2. Run: New-M365BackupApp -CertificateThumbprint ' + $cert.Thumbprint) -ForegroundColor Yellow
    }
}
