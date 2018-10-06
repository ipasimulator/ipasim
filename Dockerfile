FROM microsoft/windowsservercore:1803
LABEL Name=ipasimulator Version=0.0.1

WORKDIR "c:/project"

COPY scripts/* ./scripts/

RUN powershell -f scripts/prepare-image.ps1

CMD powershell -f scripts/build.ps1
