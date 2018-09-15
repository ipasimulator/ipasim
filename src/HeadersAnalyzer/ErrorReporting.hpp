// ErrorReporting.hpp

#ifndef ERRORREPORTING_HPP
#define ERRORREPORTING_HPP

#include <llvm/ADT/Twine.h>

void reportWarning(llvm::Twine Message);
void reportError(llvm::Twine Message);
[[noreturn]] void reportFatalError(llvm::Twine Message);

// !defined(ERRORREPORTING_HPP)
#endif
