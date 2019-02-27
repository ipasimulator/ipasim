// WrapperIndex.cpp: This file is not to be compiled into `HeadersAnalyzer`.
// Instead, it's intended to be used by `HeadersAnalyzer` when generating DLL
// wrappers. Every DLL wrapper has its own index which maps from original DLL
// RVAs to Dylib wrapper RVAs. This map is then used when calling a DLL function
// directly from some Dylib (e.g., through a pointer from Objective-C metadata).

#include "WrapperIndex.hpp"

WrapperIndex Idx;

#define ADD_LIBRARY(path) Idx.Dylibs.push_back(path)
#define MAP(dll, dylib, rva) Idx.Map[dll] = {dylib, rva}
#define END }

WrapperIndex::WrapperIndex() {
