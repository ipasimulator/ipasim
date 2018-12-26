# This script is meant to be run inside Azure VM to install and start Docker.

# Install `docker-compose`. Inspired by
# <https://docs.docker.com/compose/install/#install-compose>.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest "https://github.com/docker/compose/releases/download/1.23.2/docker-compose-Windows-x86_64.exe" -UseBasicParsing -OutFile $Env:ProgramFiles\docker\docker-compose.exe

# Start Docker. Inspired by
# <https://forums.docker.com/t/restart-docker-service-from-command-line/27331/2>.
Restart-Service "*docker*"
