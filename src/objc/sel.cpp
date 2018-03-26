#include "pch.h"
#include "objc/objc.hpp" // for SEL

const char *sel_getName(SEL sel)
{
	if (!sel) return "<null selector>";
	return (const char *)(const void *)sel;
}
