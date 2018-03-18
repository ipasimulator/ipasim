// HACK: This file must be built manually for now with the following command:
// TODO: This isn't correct and doesn't work yet.
// clang -I"..\..\lib\UnicornPort" -I"..\..\out" -F"..\..\deps\headers\iPhoneOS11.1.sdk\System\Library\Frameworks" -I"..\..\deps\headers\iPhoneOS11.1.sdk\usr\include" --target=arm-apple-darwin -w invokes.mm -o Debug\invokes.obj
// TODO: Either automatize this, or compile with HeadersAnalyzer.

#include "invokes.h"
#include "headers.inc" // headers used by the generated code

void invokes::invoke(uc_engine *uc, uint32_t address, const char *name, uint32_t &r0, uint32_t &r1, uint32_t &r2, uint32_t &r3, uint32_t r13) {
	// Define macros used by the generated code.
#define ARG(i,t) uint8_t a##i[sizeof(t)]; \
	uint32_t *p##i = reinterpret_cast<uint32_t *>(&a##i); \
	uint8_t *c##i = reinterpret_cast<uint8_t *>(&a##i); \
	t *v##i = reinterpret_cast<t *>(&a##i);
#define RET(x) auto ret = x; \
	uint32_t *retp = reinterpret_cast<uint32_t *>(&ret);

	// Include the generated code.
#include "invokes.inc"
	else { throw "function name not recognized"; }
}
