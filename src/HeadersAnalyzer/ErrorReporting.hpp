// ErrorReporting.hpp

#ifndef ERRORREPORTING_HPP
#define ERRORREPORTING_HPP

#include <llvm/ADT/Twine.h>

#include <stdexcept>

class FatalError : public std::runtime_error {
public:
  FatalError() : runtime_error("Fatal error encountered.") {}
};

void reportWarning(const llvm::Twine &Message);
void reportError(const llvm::Twine &Message);
[[noreturn]] void reportFatalError(const llvm::Twine &Message);

// !defined(ERRORREPORTING_HPP)
#endif
