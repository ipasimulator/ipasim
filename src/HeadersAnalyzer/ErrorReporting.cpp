// ErrorReporting.cpp

#include "ErrorReporting.hpp"

#include <llvm/Support/raw_ostream.h>

#include <stdexcept>

using namespace llvm;

static void print(const char *Prefix, llvm::Twine &Message) {
  errs() << Prefix << ": " << Message << ".\n";
}

void reportWarning(llvm::Twine Message) { print("Warning", Message); }
void reportError(llvm::Twine Message) { print("Error", Message); }
void reportFatalError(llvm::Twine Message) {
  print("Fatal error", Message);
  throw std::runtime_error("Fatal error encountered.");
}
