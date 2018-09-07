@echo off

:: This is here merely for testing of the Clang options. The real analyzer is
:: in project `HeadersAnalyzer`.

pushd ..\..
".\build\bin\clang" --config "src\HeadersAnalyzer\analyze_ios_headers.cfg" %*
popd
