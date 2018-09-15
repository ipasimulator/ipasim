// ErrorReporting.hpp

#ifndef ERRORREPORTING_HPP
#define ERRORREPORTING_HPP

#include <llvm/ADT/Twine.h>

void warning(llvm::Twine &Message);
void error(llvm::Twine &Message);
void fatalError(llvm::Twine &Message);

// !defined(ERRORREPORTING_HPP)
#endif
