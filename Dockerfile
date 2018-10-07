FROM microsoft/windowsservercore:1803
LABEL Name=ipasimulator Version=0.0.1

WORKDIR "c:/project"

# Install Chocolatey.
RUN powershell -c " \
    $env:chocolateyVersion = '0.10.11'; \
    $env:chocolateyUseWindowsCompression='false'; \
    Set-ExecutionPolicy Bypass -Scope Process -Force; \
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')); \
    choco feature disable --name showDownloadProgress"

# Install CMake + Ninja.
RUN powershell -c " \
    choco install cmake --version 3.12.2 -y --installargs 'ADD_CMAKE_TO_PATH=User'; \
    choco install ninja --version 1.7.2 -y"

# Install LLVM + Clang.
RUN powershell -c "choco install llvm --version 7.0.0 -y"

# Install Visual Studio Build Tools.
# TODO: Don't do this, use LLVM-only toolchain instead when possible.
# For a list of components, see
# https://docs.microsoft.com/en-us/visualstudio/install/workload-component-id-vs-build-tools?view=vs-2017.
ADD https://download.visualstudio.microsoft.com/download/pr/aa60dff5-bcbb-411c-8265-824e52a9d72f/9fa06a9b8d1721c72a87d5ae895e067f/visualstudio.15.release.chman C:/temp/visualstudio.chman
ADD https://download.visualstudio.microsoft.com/download/pr/d80c9e2f-b6f4-47cc-bc8b-1bb40ec4c92d/7189a68796aed20aabb13985c49d530b/vs_buildtools.exe C:/temp/vs_buildtools.exe
RUN powershell -c "C:/temp/vs_buildtools.exe --quiet --wait --norestart --nocache \
    --channelUri C:/temp/visualstudio.chman --installChannelUri C:/temp/visualstudio.chman \
    --add \"Microsoft.VisualStudio.Workload.VCTools;includeRecommended\""

CMD powershell -f scripts/build.ps1
