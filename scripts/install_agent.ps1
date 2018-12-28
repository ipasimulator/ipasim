# This script is meant to be run inside Azure VM to configure build agent. Don't
# forget to provide PAT as the first argument.

cd \
wget https://vstsagentpackage.azureedge.net/agent/2.144.0/vsts-agent-win-x64-2.144.0.zip -OutFile agent.zip
rm -r a
mkdir a
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory("$PWD\agent.zip", "$PWD\a")
rm agent.zip
cd a
.\config.cmd --unattended --url https://jjones.visualstudio.com --auth pat --token $args[0] --runAsService --runAsAutoLogon --pool Default --agent AzureVmAgent --replace

# Install `docker-compose`. Inspired by
# <https://docs.docker.com/compose/install/#install-compose>.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest "https://github.com/docker/compose/releases/download/1.23.2/docker-compose-Windows-x86_64.exe" -UseBasicParsing -OutFile $Env:ProgramFiles\docker\docker-compose.exe

# Start Docker. Inspired by
# <https://forums.docker.com/t/restart-docker-service-from-command-line/27331/2>.
Start-Service docker
