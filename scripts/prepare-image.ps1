## See [docker-script].

# Install Chocolatey.
$env:chocolateyVersion = '0.10.11'
$env:chocolateyUseWindowsCompression='false'
Set-ExecutionPolicy Bypass -Scope Process -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco feature disable --name showDownloadProgress

# Install build tools.
choco install cmake --version 3.12.2 -y --installargs 'ADD_CMAKE_TO_PATH=User'
choco install ninja --version 1.7.2 -y
