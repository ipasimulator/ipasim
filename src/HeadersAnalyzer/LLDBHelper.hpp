// LLDBHelper.hpp

#ifndef LLDBHELPER_HPP
#define LLDBHELPER_HPP

#include <lldb/Core/Debugger.h>

class LLDBHelper {
public:
  LLDBHelper();
  ~LLDBHelper();

private:
  lldb::DebuggerSP Debugger;
};

// !defined(LLDBHELPER_HPP)
#endif
