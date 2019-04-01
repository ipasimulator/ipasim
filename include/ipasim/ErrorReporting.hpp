// ErrorReporting.hpp

#ifndef IPASIM_ERROR_REPORTING_HPP
#define IPASIM_ERROR_REPORTING_HPP

#include <filesystem>
#include <llvm/ADT/Twine.h>
#include <llvm/Support/raw_ostream.h>
#include <stdexcept>
#include <string>

namespace ipasim {

class FatalError : public std::runtime_error {
public:
  FatalError() : runtime_error("Fatal error encountered.") {}
};

void reportWarning(const llvm::Twine &Message);
void reportError(const llvm::Twine &Message);
[[noreturn]] void reportFatalError(const llvm::Twine &Message);
void reportStatus(const llvm::Twine &Message);

// TODO: Move to a better place.
std::unique_ptr<llvm::raw_fd_ostream> createOutputFile(const std::string &Path);
std::filesystem::path createOutputDir(const char *Path);

} // namespace ipasim

// !defined(IPASIM_ERROR_REPORTING_HPP)
#endif
