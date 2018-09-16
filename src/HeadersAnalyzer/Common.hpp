// Common.hpp

#ifndef COMMON_HPP
#define COMMON_HPP

#include <llvm/Support/raw_ostream.h>

#include <cstdint>
#include <filesystem>
#include <string>

// Prefix and postfix operators.
#define prefix(op) &operator op()
#define postfix(op) operator op(int)

// Filesystem.
std::unique_ptr<llvm::raw_fd_ostream> createOutputFile(const std::string &Path);
std::filesystem::path createOutputDir(const char *Path);

// Strings.
// `constexpr` `strlen`. Usage: `constexpr size_t len = length(ConstExprVar);`.
size_t constexpr length(const char *S) { return *S ? 1 + length(S + 1) : 0; }

// !defined(COMMON_HPP)
#endif
