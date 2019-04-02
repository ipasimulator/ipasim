// WrapperIndex.cpp: This file is not to be compiled into `HeadersAnalyzer`.
// Instead, it's intended to be used by `HeadersAnalyzer` when generating DLL
// wrappers. Every DLL wrapper has its own index which maps from original DLL
// RVA to Dylib wrapper where it's used. This map is then used when calling a
// DLL function directly from some Dylib (e.g., through a pointer from
// Objective-C metadata).

#include "ipasim/WrapperIndex.hpp"

using namespace ipasim;

__declspec(dllexport) WrapperIndex Idx;

#define ADD_LIBRARY(path) Idx.Dylibs.push_back(path)
#define MAP(dll, dylib) Idx.Map[dll] = dylib
#define END }

WrapperIndex::WrapperIndex() {
