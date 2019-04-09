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
set GIT_ASKPASS=%CD%\git_askpass_helper.cmd
if exist .\IPASimulator\ (
    rem See #14.
    cd IPASimulator
    git pull --recurse-submodules
) else (
    git clone --depth 1 --recurse-submodules --shallow-submodules ^
https://jjones.visualstudio.com/DefaultCollection/IPASimulator/_git/IPASimulator
    cd IPASimulator
)

if [%BUILD_TABLEGENS_ONLY%]==[1] (
    rem Use only sample build command. See `scripts/build.ps1` in repository
    rem IPASimulator.
    echo BUILD_TABLEGENS_ONLY=1 >.env
) else (
    del .env 2>NUL
)

rem Build.
docker login -u janjones -p %DOCKER_PASSWORD%
if [%PULL_BUILD_ARTIFACTS%]==[1] (
    docker pull janjones/ipasim:artifacts
    docker tag janjones/ipasim:artifacts janjones/ipasim
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
docker tag janjones/ipasim:latest janjones/ipasim:%BUILD_BUILDNUMBER%
docker commit ipasimulator_ipasim_1^
 janjones/ipasim:artifacts-%BUILD_BUILDNUMBER%
docker tag janjones/ipasim:artifacts-%BUILD_BUILDNUMBER%^
 janjones/ipasim:artifacts
docker push janjones/ipasim:%BUILD_BUILDNUMBER%
docker push janjones/ipasim:latest
docker push janjones/ipasim:artifacts-%BUILD_BUILDNUMBER%
docker push janjones/ipasim:artifacts

rem Shutdown.
if [%SHUTDOWN_WHEN_COMPLETE%]==[1] shutdown /p

:END
exit /b %EXIT_ERRORLEVEL%
