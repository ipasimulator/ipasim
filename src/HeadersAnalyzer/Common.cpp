// Common.cpp

#include "Common.hpp"

#include "ErrorReporting.hpp"

#include <llvm/Support/FileSystem.h>

#include <system_error>

using namespace llvm;
using namespace std;
using namespace std::filesystem;

unique_ptr<raw_fd_ostream> createOutputFile(const string &Path) {
  error_code EC;
  auto OS(std::make_unique<raw_fd_ostream>(Path, EC, sys::fs::F_None));
  if (EC) {
    reportError(Twine("cannot create output file (") + Path +
                "): " + EC.message());
    return nullptr;
  }
  return move(OS);
}

path createOutputDir(const char *Path) {
  path P(Path);
  error_code E;
  if (!create_directories(P, E) && E) {
    reportFatalError(Twine("cannot create output directory (") + Path +
                     "): " + E.message());
  }
  return move(P);
}
