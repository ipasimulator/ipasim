// ErrorReporting.cpp

#include "ErrorReporting.hpp"

#include <llvm/Support/raw_ostream.h>

using namespace llvm;

static void print(const char *Prefix, llvm::Twine &Message) {
  errs() << Prefix << ": " << Message << '\n';
}

void warning(llvm::Twine &Message) { print("Warning", Message); }
void error(llvm::Twine &Message) { print("Error", Message); }
void fatalError(llvm::Twine &Message) { print("Fatal error", Message); }
