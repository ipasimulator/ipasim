// IpaSimulator/Config.hpp: Contains configuration switches for library
// `IpaSimLibrary`.

#ifndef IPASIM_IPA_SIMULATOR_CONFIG_HPP
#define IPASIM_IPA_SIMULATOR_CONFIG_HPP

#include "ipasim/Common.hpp"

namespace ipasim {

#if !defined(IPASIM_PRINT_ALL)
#define IPASIM_PRINT_ALL 0
#endif

#if !defined(IPASIM_PRINT_INSTRUCTIONS)
#define IPASIM_PRINT_INSTRUCTIONS IPASIM_PRINT_ALL
#endif
constexpr bool PrintInstructions = IPASIM_PRINT_INSTRUCTIONS;

#if !defined(IPASIM_PRINT_MEMORY_WRITES)
#define IPASIM_PRINT_MEMORY_WRITES IPASIM_PRINT_ALL
#endif
constexpr bool PrintMemoryWrites = IPASIM_PRINT_MEMORY_WRITES;

#if !defined(IPASIM_PRINT_EMU_INFO)
#define IPASIM_PRINT_EMU_INFO IPASIM_PRINT_ALL
#endif
constexpr bool PrintEmuInfo = IPASIM_PRINT_EMU_INFO;

} // namespace ipasim

// !defined(IPASIM_IPA_SIMULATOR_CONFIG_HPP)
#endif
