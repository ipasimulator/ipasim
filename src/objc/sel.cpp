#include "pch.h"
#include "objc/objc.hpp" // for function definitions

const char *sel_getName(SEL sel)
{
	if (!sel) return "<null selector>";
	return (const char *)(const void *)sel;
}
