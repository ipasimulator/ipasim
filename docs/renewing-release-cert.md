# Renewing released certificate

Certificate is shipped alongside [released binaries](https://github.com/ipasimulator/ipasim/releases).
It can expire.
Following steps can be used to renew the certificate.

It is just a development certificate, so anyone can renew it
(see [Create a certificate for package signing](https://docs.microsoft.com/en-us/windows/msix/package/create-certificate-package-signing))
and re-sign the app package
(see [Sign an app package using SignTool](https://docs.microsoft.com/en-us/windows/msix/package/sign-app-package-using-signtool)).

1. Install [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/sdk-archive/), version 10.0.18362.1.
   It should be available under this link:
   <https://go.microsoft.com/fwlink/?linkid=2083338>.
   Its `signtool.exe` will be used below.
   Note that "Windows SDK for Desktop x86 Apps" workload needs to be installed.
2. Download your chosen [release](https://github.com/ipasimulator/ipasim/releases), i.e., `ipasim-build-v*.zip`.
3. Extract it and navigate to folder with the package (`.msix` file).
4. Open elevated PowerShell in that folder.
5. Replace path to `signtool` depending on your installed Windows SDK in the following script (3rd line) and then execute it:

   ```ps1
   $cert = New-SelfSignedCertificate -Type Custom -Subject "CN=jjone" -KeyUsage DigitalSignature -FriendlyName "ipaSim" -CertStore Cert:\CurrentUser\My\ -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
   Export-PfxCertificate -cert $cert -FilePath key.pfx -Password $(ConvertTo-SecureString -String "ipaSim" -Force -AsPlainText)
   & 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\x64\signtool.exe' sign /fd sha256 /a /f key.pfx /p ipaSim .\IpaSimApp_*.msix
   Remove-Item key.pfx
   Export-Certificate -Cert $cert -FilePath (Get-ChildItem .\IpaSimApp_*.cer).name
   Remove-Item $cert.PSPath
   ```

6. The certificate (`.cer` file) should be renewed and the app package (`.msix` file) signed. You can now install the app by executing `./Add-AppDevPackage.ps1` as usual.
