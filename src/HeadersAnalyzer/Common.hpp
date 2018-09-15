// Common.hpp

#ifndef COMMON_HPP
#define COMMON_HPP

#include <llvm/Support/raw_ostream.h>

#include <filesystem>

// Prefix and postfix operators.
#define prefix(op) &operator op()
#define postfix(op) operator op(int)

// Filesystem.
std::unique_ptr<llvm::raw_fd_ostream> createOutputFile(const std::string &Path);
std::filesystem::path createOutputDir(const char *Path);

// !defined(COMMON_HPP)
#endif
