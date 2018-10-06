FROM microsoft/windowsservercore:1803
LABEL Name=ipasimulator Version=0.0.1

VOLUME "c:/project"
WORKDIR "c:/project"

CMD powershell -f scripts/docker.ps1
