// Build via `build_invokes.cmd`.

#include <cstring>
#include "invokes.h"
#include "headers.inc" // headers used by the generated code

bool invokes::invoke(uc_engine *uc, const char *module, uint64_t address, uint32_t &r0, uint32_t &r1, uint32_t &r2, uint32_t &r3, uint32_t r13) {
	// Define macros used by the generated code.
#define ARG(i,t) using u##i = t; \
    uint8_t a##i[sizeof(u##i)]; \
    uint32_t *p##i = reinterpret_cast<uint32_t *>(&a##i); \
    uint8_t *c##i = reinterpret_cast<uint8_t *>(&a##i); \
    u##i *v##i = reinterpret_cast<u##i *>(&a##i);
#define RET(x) auto ret = x; \
    uint32_t *retp = reinterpret_cast<uint32_t *>(&ret);

    // Include the generated code.
#include "invokes.inc"
    else { return false; }
    return true;
}
