@echo off

echo.
echo Pushing "%1"...
echo.

pushd %1
git push
git pushgtm
popd
