// ErrorReporting.cpp

#include "ErrorReporting.hpp"

#include "Config.hpp"

#include <llvm/Support/raw_ostream.h>

using namespace llvm;

static void print(raw_ostream &OS, const char *Prefix, const Twine &Message) {
  OS << Prefix << ": " << Message << ".\n";
  OS.flush();
}
static void printError(const char *Prefix, const Twine &Message) {
  if constexpr (!IgnoreErrors) {
    print(errs(), Prefix, Message);
  }
}
static void printOutput(const char *Prefix, const Twine &Message) {
  print(outs(), Prefix, Message);
}

void reportWarning(const Twine &Message) { printError("Warning", Message); }
void reportError(const Twine &Message) { printError("Error", Message); }
void reportFatalError(const Twine &Message) {
  printError("Fatal error", Message);
  throw FatalError();
}
void reportStatus(const Twine &Message) {
  printOutput("Status", Message + "..");
}
