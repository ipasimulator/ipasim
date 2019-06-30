@echo off

rem Check that Docker is running before doing anything else.
docker ps
if %ERRORLEVEL% NEQ 0 (
    set EXIT_ERRORLEVEL=%ERRORLEVEL%
    sc query docker
    goto END
)

rem Clean repository. Double `f` ensures that also git subdirs are removed.
if [%RESET_REPOSITORY%]==[1] (
    git clean -qffdx
) else (
    git clean -qfdx
)

rem Install Git LFS.
git lfs install

rem Clone sources.
if exist .\ipasim\ (
    rem See #14.
    cd ipasim
    git pull --recurse-submodules
) else (
    rem TODO: Clone the current branch.
    git clone --depth 1 --recurse-submodules --shallow-submodules ^
https://github.com/ipasimulator/ipasim
    cd ipasim
)

if [%BUILD_TABLEGENS_ONLY%]==[1] (
    rem Use only sample build command. See `scripts/build.ps1` in repository
    rem IPASimulator.
    echo BUILD_TABLEGENS_ONLY=1 >.env
) else (
    del .env 2>NUL
)

rem Build.
docker login -u ipasim -p %DOCKER_PASSWORD%
if [%PULL_BUILD_ARTIFACTS%]==[1] (
    docker pull ipasim/artifacts
    docker tag ipasim/artifacts ipasim/build
    set DOCKER_COMPOSE_OPTIONS=--no-build
) else if [%PULL_DOCKER_IMAGE%]==[1] (
    docker-compose pull
    set DOCKER_COMPOSE_OPTIONS=--no-build
) else (
    set DOCKER_COMPOSE_OPTIONS=--build
)
docker-compose up --exit-code-from ipasim %DOCKER_COMPOSE_OPTIONS%
set EXIT_ERRORLEVEL=%ERRORLEVEL%

rem Push artifacts.
docker commit ipasimulator_ipasim_1 ipasim/artifacts:%BUILD_BUILDNUMBER%
if %ERRORLEVEL% NEQ 0 (
    set EXIT_ERRORLEVEL=%ERRORLEVEL%
    goto CLEANUP
)
docker tag ipasim/build:latest ipasim/build:%BUILD_BUILDNUMBER%
docker tag ipasim/artifacts:%BUILD_BUILDNUMBER% ipasim/artifacts
docker push ipasim/build:%BUILD_BUILDNUMBER%
docker push ipasim/artifacts:%BUILD_BUILDNUMBER%

rem Don't push latest `build` and `artifacts` tags for unsuccessful builds.
if %EXIT_ERRORLEVEL% EQU 0 (
    docker push ipasim/build
    docker push ipasim/artifacts
)

rem Cleanup images.
:CLEANUP
docker rm ipasimulator_ipasim_1
docker image rm ipasim/build ipasim/build:%BUILD_BUILDNUMBER% ipasim/artifacts^
 ipasim/artifacts:%BUILD_BUILDNUMBER%

rem Shutdown.
if [%SHUTDOWN_WHEN_COMPLETE%]==[1] shutdown /p

:END
exit /b %EXIT_ERRORLEVEL%
