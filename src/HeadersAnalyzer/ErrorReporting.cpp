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

namespace {

class raw_std_ostream : public raw_ostream {
public:
  raw_std_ostream(StdStream &Str) : Str(Str) {}

private:
  StdStream &Str;

  void write_impl(const char *Ptr, size_t Size) override {
    if (Ptr[Size] == 0)
      // `Ptr` is a null-terminated string.
      Str << Ptr;
    else
      // We must copy `Ptr` to a new null-terminated string.
      Str << string(Ptr, Size).c_str();
  }
  uint64_t current_pos() const override {
    throw logic_error("Function `current_pos` is unimplemented.");
  }
};

} // namespace

StdLogger ipasim::Log = StdLogger(StdStream::out(), StdStream::err());

StdStream &ipasim::operator<<(StdStream &Str, llvm::Twine &T) {
  raw_std_ostream OS(Str);
  OS << T;
  return Str;
}

unique_ptr<raw_fd_ostream> ipasim::createOutputFile(const string &Path) {
  error_code EC;
  auto OS(std::make_unique<raw_fd_ostream>(Path, EC, sys::fs::F_None));
  if (EC) {
    Log.error() << "cannot create output file (" << Path
                << "): " << EC.message() << Log.end();
    return nullptr;
  }
  return move(OS);
}

path ipasim::createOutputDir(const char *Path) {
  path P(Path);
  error_code E;
  if (!create_directories(P, E) && E) {
    Log.error() << "cannot create output directory (" << Path
                << "): " << E.message() << Log.fatalEnd();
  }
  return move(P);
}
