@echo off

pushd ..\..
".\build\bin\clang" --config "src\HeadersAnalyzer\analyze_ios_headers.cfg" %*
popd
