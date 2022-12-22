Set-StrictMode -version 2.0
$ErrorActionPreference = "Stop"

# Determine latest tag name.
$tagName = $(gh release view --json tagName --template '{{ .tagName }}')

# Download release ZIP.
$zipName = "ipasim-build-$tagName.zip"
gh release download "$tagName" --pattern "$zipName" || $(exit 1)

# Extract the ZIP (the content will be in `build` subdirectory).
Expand-Archive -Path "$zipName" -DestinationPath "." -Force

# Create new certificate.
$cert = New-SelfSignedCertificate -Type Custom -Subject "CN=jjone" -KeyUsage DigitalSignature -FriendlyName "ipaSim" -CertStore Cert:\CurrentUser\My\ -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
Export-PfxCertificate -cert $cert -FilePath ".\key.pfx" -Password $(ConvertTo-SecureString -String "ipaSim" -Force -AsPlainText)

# Find latest installed Windows SDK.
$windowsSdkPath = "$(Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.*\' | Select-Object -Last 1)"

# Sign the MSIX package using Windows SDK.
& "$windowsSdkPath\x64\signtool.exe" sign /fd "sha256" /a /f ".\key.pfx" /p "ipaSim" ".\build\*.msix" || $(exit 1)

# Convert to `.cer` file (replace the old one).
Export-Certificate -Cert $cert -FilePath (Get-ChildItem ".\build\*.cer")

# Re-pack the release ZIP.
$timestamp = (Get-Date).ToString("yyyy-MM-dd")
$zipNameUpdated = "ipasim-build-$tagName-$timestamp.zip"
Compress-Archive -Path ".\build" -DestinationPath "$zipNameUpdated"

# Upload the new release ZIP.
gh release upload "$tagName" "$zipNameUpdated" || $(exit 1)
