#include "objc/objc.hpp" // for function definitions
#include "objc/locks.hpp" // for selLock

static NXMapTable *namedSelectors;

const char *sel_getName(SEL sel)
{
    if (!sel) return "<null selector>";
    return (const char *)(const void *)sel;
}

static SEL __sel_registerName(const char *name, int lock, int copy)
{
    // CHANGE: "search_builtins" calls were removed, since they did nothing
    // useful when SUPPORT_PREOPT was 0, which it is here, anyway.

    SEL result = 0;

    if (lock) selLock.assertUnlocked();
    else selLock.assertWriting();

    if (!name) return (SEL)0;

    // CHANGE: "search_builtins" call removed.

    if (lock) selLock.read();
    if (namedSelectors) {
        result = (SEL)NXMapGet(namedSelectors, name);
    }
    if (lock) selLock.unlockRead();
    if (result) return result;

    // No match. Insert.

    if (lock) selLock.write();

    if (!namedSelectors) {
        namedSelectors = NXCreateMapTable(NXStrValueMapPrototype,
            (unsigned)SelrefCount);
    }
    if (lock) {
        // Rescan in case it was added while we dropped the lock
        result = (SEL)NXMapGet(namedSelectors, name);
    }
    if (!result) {
        result = sel_alloc(name, copy);
        // fixme choose a better container (hash not map for starters)
        NXMapInsert(namedSelectors, sel_getName(result), result);
    }

    if (lock) selLock.unlockWrite();
    return result;
}
