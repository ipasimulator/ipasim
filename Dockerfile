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

# HACK: Ideally, we would like to use `-DCMAKE_RC_COMPILER=llvm-rc`, but it
# currently doesn't work - see
# <https://gitlab.kitware.com/cmake/cmake/issues/17804>. So, at least for now,
# we add a symlink `rc` -> `llvm-rc`.
RUN mklink "C:/Program Files/LLVM/bin/rc.exe" "C:/Program Files/LLVM/bin/llvm-rc.exe"

CMD powershell -f scripts/build.ps1
