// HeadersAnalyzer.cpp : Defines the entry point for the console application.
//

#include <clang/Frontend/CompilerInstance.h>

using namespace clang;
using namespace llvm;

int main()
{
    CompilerInstance ci;
    ci.createDiagnostics();

    return 0;
}
