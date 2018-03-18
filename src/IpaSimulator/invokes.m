// TODO: This is an Objective-C code, compile it as such!

#include "pch.h"
#include "invokes.h"
#include "headers.inc"

void invokes::invoke(uc_engine *uc, uint32_t address, uint32_t &r0, uint32_t &r1, uint32_t &r2, uint32_t &r3, uint32_t r13) {
	// Define macros used by the generated code.
#define ARG(i,t) uint8_t a##i[sizeof(t)]; \
	uint32_t *p##i = reinterpret_cast<uint32_t *>(&a##i); \
	uint8_t *c##i = reinterpret_cast<uint8_t *>(&a##i); \
	t *v##i = reinterpret_cast<t *>(&a##i);
#define RET(x) auto ret = x; \
	uint32_t *pret = reinterpret_cast<uint32_t *>(&ret);

#include "invokes.inc"
}
