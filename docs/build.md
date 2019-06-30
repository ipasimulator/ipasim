# Build instructions

## Prerequisites

1. Install [Docker Desktop for
   Windows](https://hub.docker.com/editions/community/docker-ce-desktop-windows).
2. [Switch to Windows
   containers](https://docs.docker.com/docker-for-windows/#switch-between-windows-and-linux-containers).
3. Install [Visual Studio](https://visualstudio.microsoft.com/) (around version
   2019).

## Build process

Inside the repository root, run:

```bash
docker-compose build
docker-compose run --name ipasim ipasim powershell
```

Once inside the built container, run:

```bash
./scripts/build.ps1
./scripts/extract.ps1 Release
```

Finally, open `src/IpaSimulator/IpaSimApp.sln` in Visual Studio and run it (in
configuration `Release`). Alternatively, you can use `Debug` configuration, but
then you have to execute command `./scripts/extract.ps1 Debug` instead of the
one mentioned above.

If you don't want to build everything from scratch, you can [use prebuilt
artifacts](artifacts.md).
