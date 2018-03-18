#ifndef _H_INVOKES
#define _H_INVOKES

#include <stdint.h>
#include <unicorn/unicorn.h>

class invokes {
public:
	static void invoke(uc_engine *uc, uint32_t address, uint32_t &r0, uint32_t &r1, uint32_t &r2, uint32_t &r3, uint32_t r13);
};

#endif
