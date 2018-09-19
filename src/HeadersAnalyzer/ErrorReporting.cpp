// ErrorReporting.cpp

#include "ErrorReporting.hpp"

#include <llvm/Support/raw_ostream.h>

using namespace llvm;

static void print(const char *Prefix, const Twine &Message) {
  outs().flush();
  errs() << Prefix << ": " << Message << ".\n";
  errs().flush();
}

void reportWarning(const Twine &Message) { print("Warning", Message); }
void reportError(const Twine &Message) { print("Error", Message); }
void reportFatalError(const Twine &Message) {
  print("Fatal error", Message);
  throw FatalError();
}
