# Building notes

In this document, we describe some advanced building scenarios. Basic building
instructions [are available elsewhere](build.md).

Install and run Docker for Windows (tested with version `18.06.1-ce-win73`),
enable Windows containers,
[increase maximum container disk size](https://docs.microsoft.com/en-us/visualstudio/install/build-tools-container?view=vs-2017#step-4-expand-maximum-container-disk-size)
and run `docker-compose up`. If you change `Dockerfile`, you'll need to run
`docker-compose up --build` to rebuild the Docker image. To run some other
commands instead of `build.ps1`, run
`docker-compose run --rm ipasim powershell`. To re-build, delete the folder
`cmake` (`rm -r cmake` from PowerShell). To build manually, just execute the
script `build.ps1` (`.\scripts\build.ps1` from PowerShell inside the container).
To run commands in a container repeatedly, first run
`docker-compose run --name ipasim ipasim powershell` (i.e., without option
`--rm`) and then (after exiting the container) run `docker start -ai ipasim`.

When we have our Docker machine up and running, we can start building. First,
run `.\scripts\build.ps1` inside `C:\ipaSim\src`. That script creates build
directory `C:\ipaSim\build`. Inside that directory, run
`ninja config-ipaSim-x86-Debug` to prepare building of that configuration (x86
Debug). Then, move to `C:\ipaSim\build\ipaSim-x86-Debug` and continue using
Ninja from there (e.g., run `ninja -t targets` to see list of possible build
targets). To enable incremental builds across Docker builds, use scripts
`C:\ipaSim\src\scripts\backup.ps1` and `C:\ipaSim\src\scripts\restore.ps1`. See
[issue #3](issues/3.md) for more details.
