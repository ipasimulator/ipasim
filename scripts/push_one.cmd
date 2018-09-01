@echo off

pushd %1

rem Find out if there is anything to be pushed via (fast) command `git status`.
git status | find /C "branch is ahead" >NUL
if %errorlevel% equ 0 (goto push) else (goto dont_push)

:dont_push

echo.
echo Nothing to push in "%1".
echo.

goto end

rem If there is something to push, call (slow) command `git push`.
:push

echo.
echo Pushing "%1"...
echo.

git push
git pushgtm

:end
popd
