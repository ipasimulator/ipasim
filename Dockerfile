# We use image based on `microsoft/windowsservercore:ltsc2016` instead of
# `microsoft/windowsservercore:1803` because of this issue:
# https://github.com/moby/moby/issues/37283. The image we use is
# `microsoft/dotnet-framework:3.5-sdk-windowsservercore-ltsc2016`.
FROM microsoft/dotnet-framework@sha256:5637aa0d24af7d5d3c1726f1c280bbedf39cc8927364e5c3012d14b71c2ffce4
LABEL Name=ipasimulator Version=0.0.1

SHELL ["cmd", "/S", "/C"]
WORKDIR c:/ipaSim/src

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

# Install Python. It's needed to build LLVM and Clang.
RUN powershell -c "choco install python --version 3.7.0 -y"

# Install NuGet.
RUN powershell -c "choco install nuget.commandline --version 4.9.1 -y"

# Install C++/WinRT.
# TODO: Use the one from Windows SDK when we use some newer version of the SDK.
RUN powershell -c "nuget install cppwinrt -Version 2017.4.6.1 -OutputDirectory C:/packages"

# Install Node.js LTS.
ADD https://nodejs.org/dist/v8.11.3/node-v8.11.3-x64.msi C:/temp/node-install.msi
RUN start /wait msiexec.exe /i C:/temp/node-install.msi /l*vx "C:/temp/MSI-node-install.log" /qn ADDLOCAL=ALL

# Install Visual Studio Build Tools.
# TODO: Don't do this, use LLVM-only toolchain instead when possible.
# For a list of components, see <https://docs.microsoft.com/en-us/visualstudio/
# install/workload-component-id-vs-build-tools?view=vs-2017>. For more
# information, see <https://blogs.msdn.microsoft.com/heaths/2018/06/14/
# no-container-image-for-build-tools-for-visual-studio-2017/> or <https://
# docs.microsoft.com/en-us/visualstudio/install/
# build-tools-container?view=vs-2017> or <https://github.com/Microsoft/
# vs-dockerfiles/tree/5f5c58248a97e881273bebe94fdaaca640d75002/native-desktop>.
# TODO: Maybe execute the following in a new container based on image from
# previous steps which would also have a volume in C:/vscache and use that for,
# as its name suggests, cache of the Visual Studio Installer, so that it doesn't
# have to download everything over and over again.
# See also i16.
COPY scripts/install_vs.cmd C:/temp/
ADD https://download.microsoft.com/download/8/3/4/834E83F6-C377-4DCE-A757-69A418B6C6DF/Collect.exe C:/temp/collect.exe
ADD https://download.visualstudio.microsoft.com/download/pr/7ce359b9-c96f-43bd-aa85-386a3e6af941/40e7e21dabde5db7c06f04e6710cad28/visualstudio.15.release.chman C:/temp/visualstudio.chman
ADD https://download.visualstudio.microsoft.com/download/pr/a46d2db7-bd7b-43ee-bd7b-12624297e4ec/11b9c9bd44ec2b475f6da3d1802b3d00/vs_buildtools.exe C:/temp/vs_buildtools.exe
RUN C:/temp/install_vs.cmd C:/temp/vs_buildtools.exe --quiet --wait --norestart --nocache \
    --path install="C:/BuildTools" \
    --channelUri C:/temp/visualstudio.chman --installChannelUri C:/temp/visualstudio.chman \
    --add Microsoft.VisualStudio.Component.VC.CoreBuildTools \
    --add Microsoft.VisualStudio.Component.VC.Redist.14.Latest \
    --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 \
    --add Microsoft.VisualStudio.Component.VC.ATLMFC \
    --add Microsoft.VisualStudio.Component.Windows10SDK.17134

# Install ANGLE.WindowsStore. It's needed by project OpenGLES in WinObjC.
RUN powershell -c "nuget install ANGLE.WindowsStore -Version 2.1.13 -OutputDirectory C:/packages"

# Install Remote Tools for Visual Studio 2017. They can be used for debugging.
# See https://www.richard-banks.org/2017/02/debug-net-in-windows-container.html.
ADD https://download.visualstudio.microsoft.com/download/pr/4757630b-d5e2-400c-b1dd-9915b00593bf/2e4ed68951cd6cebb248a862d43a6d84/vs_remotetools.exe C:/temp/vs_remotetools.exe
RUN C:/temp/vs_remotetools.exe /install /quiet
EXPOSE 4022 4023

# Install `cppcheck`. It's needed to compile LIEF.
RUN powershell -c "choco install cppcheck --version 1.87 -y"

# Install Git. It's needed to compile LIEF.
RUN powershell -c "choco install git --version 2.20.1 -y"

# Start developer command prompt.
ENTRYPOINT C:/BuildTools/Common7/Tools/VsDevCmd.bat -arch=x86 -host_arch=x86 &&

CMD powershell -f scripts/build.ps1
