## See [docker-script].

# Install Chocolatey.
$env:chocolateyVersion = '0.10.11'
$env:chocolateyUseWindowsCompression='false'
Set-ExecutionPolicy Bypass -Scope Process -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco feature disable --name showDownloadProgress

# Make `refreshenv` available right away, by defining the
# $env:ChocolateyInstall variable and importing the Chocolatey profile module.
# See https://stackoverflow.com/a/46760714
$env:ChocolateyInstall = Convert-Path "$((Get-Command choco).path)\..\.."
Import-Module "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"

# Install build tools.
choco install cmake --version 3.12.2 -y --installargs 'ADD_CMAKE_TO_PATH=User'
refreshenv
