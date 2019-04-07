// Config.hpp

#ifndef IPASIM_IPA_SIMULATOR_CONFIG_HPP
#define IPASIM_IPA_SIMULATOR_CONFIG_HPP

#include "ipasim/Common.hpp"

#if !defined(IPASIM_PRINT_INSTRUCTIONS)
#define IPASIM_PRINT_INSTRUCTIONS 0
#endif
constexpr bool PrintInstructions = IPASIM_PRINT_INSTRUCTIONS;

#if !defined(IPASIM_PRINT_MEMORY_WRITES)
#define IPASIM_PRINT_MEMORY_WRITES 0
#endif
constexpr bool PrintMemoryWrites = IPASIM_PRINT_MEMORY_WRITES;

// !defined(IPASIM_IPA_SIMULATOR_CONFIG_HPP)
#endif
