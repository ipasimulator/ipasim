// ErrorReporting.cpp

#include "ipasim/ErrorReporting.hpp"

#include "ipasim/HeadersAnalyzer/Config.hpp"

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <system_error>

using namespace ipasim;
using namespace llvm;
using namespace std;
using namespace std::filesystem;

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

void ipasim::reportWarning(const Twine &Message) {
  printError("Warning", Message);
}
void ipasim::reportError(const Twine &Message) { printError("Error", Message); }
void ipasim::reportFatalError(const Twine &Message) {
  printError("Fatal error", Message);
  throw FatalError();
}
void ipasim::reportStatus(const Twine &Message) {
  printOutput("Status", Message + "..");
}

unique_ptr<raw_fd_ostream> ipasim::createOutputFile(const string &Path) {
  error_code EC;
  auto OS(std::make_unique<raw_fd_ostream>(Path, EC, sys::fs::F_None));
  if (EC) {
    reportError(Twine("cannot create output file (") + Path +
                "): " + EC.message());
    return nullptr;
  }
  return move(OS);
}

path ipasim::createOutputDir(const char *Path) {
  path P(Path);
  error_code E;
  if (!create_directories(P, E) && E) {
    reportFatalError(Twine("cannot create output directory (") + Path +
                     "): " + E.message());
  }
  return move(P);
}
