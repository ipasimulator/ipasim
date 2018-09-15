// ClangHelper.hpp

#ifndef CLANGHELPER_HPP
#define CLANGHELPER_HPP

#include "LLVMHelper.hpp"

#include <clang/Frontend/CompilerInstance.h>

using namespace clang;

class ClangHelper {
public:
  ClangHelper(LLVMInitializer &);

private:
  CompilerInstance CI;
};

// !defined(CLANGHELPER_HPP)
#endif
