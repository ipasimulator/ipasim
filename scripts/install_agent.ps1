# This script is meant to be run inside Azure VM to configure build agent. Don't
# forget to provide `$env:AZURE_PAT`.

wget https://vstsagentpackage.azureedge.net/agent/2.144.0/vsts-agent-win-x64-2.144.0.zip -OutFile agent.zip
mkdir agent
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory("$PWD\agent.zip", "$PWD\agent")
rm agent.zip
cd agent
.\config.cmd --unattended --url https://jjones.visualstudio.com --auth pat --token $env:AZURE_PAT --runAsService --runAsAutoLogon --pool Default --agent AzureVmAgent
