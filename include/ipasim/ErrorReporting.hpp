// ErrorReporting.hpp

#ifndef IPASIM_ERROR_REPORTING_HPP
#define IPASIM_ERROR_REPORTING_HPP

#include "ipasim/Logger.hpp"

#include <filesystem>
#include <llvm/ADT/Twine.h>
#include <llvm/Support/raw_ostream.h>
#include <stdexcept>
#include <string>

namespace ipasim {

extern StdLogger Log;

StdStream &operator<<(StdStream &Str, llvm::Twine &T);

// TODO: Move to a better place.
std::unique_ptr<llvm::raw_fd_ostream> createOutputFile(const std::string &Path);
std::filesystem::path createOutputDir(const char *Path);

} // namespace ipasim

// !defined(IPASIM_ERROR_REPORTING_HPP)
#endif
