// HACK: This file must be built manually for now with the following command (on macOS):
// clang -w -c -arch i386 invokes.mm
// Then converted to .obj by using objconv like this:
// objconv -fpe32 -nr:__ZN7invokes6invokeEP9uc_structyPKcRjS4_S4_S4_j:?invoke@invokes@@SA_NPAUuc_struct@@_KPBDAAI333I@Z invokes.o invokes.obj
// TODO: Either automatize this, or compile with HeadersAnalyzer.

#include "invokes.h"
#include "headers.inc" // headers used by the generated code

bool invokes::invoke(uc_engine *uc, uint64_t address, const char *name, uint32_t &r0, uint32_t &r1, uint32_t &r2, uint32_t &r3, uint32_t r13) {
	// Define macros used by the generated code.
#define ARG(i,t) uint8_t a##i[sizeof(t)]; \
	uint32_t *p##i = reinterpret_cast<uint32_t *>(&a##i); \
	uint8_t *c##i = reinterpret_cast<uint8_t *>(&a##i); \
	t *v##i = reinterpret_cast<t *>(&a##i);
#define RET(x) auto ret = x; \
	uint32_t *retp = reinterpret_cast<uint32_t *>(&ret);

	// Include the generated code.
#include "invokes.inc"
    else { return false; }
    return true;
}
