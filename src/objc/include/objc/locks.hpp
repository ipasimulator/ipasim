#ifndef OBJC_LOCKS_H
#define OBJC_LOCKS_H

#include <pthread.h>

// [Apple] Mix-in for classes that must not be copied.
class nocopy_t {
private:
	nocopy_t(const nocopy_t&) = delete;
	const nocopy_t& operator=(const nocopy_t&) = delete;
protected:
	nocopy_t() {}
	~nocopy_t() {}
};

template <bool Debug> class rwlock_tt;

#if DEBUG
#   define LOCKDEBUG 1
#else
#	define LOCKDEBUG 0
#endif

using rwlock_t = rwlock_tt<LOCKDEBUG>;

// CHANGE: "extern" keyword was removed from these definitions,
// since it was most likely redundant.
void lockdebug_remember_rwlock(rwlock_tt<true> *lock);
void lockdebug_rwlock_read(rwlock_tt<true> *lock);
void lockdebug_rwlock_try_read_success(rwlock_tt<true> *lock);
void lockdebug_rwlock_unlock_read(rwlock_tt<true> *lock);
void lockdebug_rwlock_write(rwlock_tt<true> *lock);
void lockdebug_rwlock_try_write_success(rwlock_tt<true> *lock);
void lockdebug_rwlock_unlock_write(rwlock_tt<true> *lock);
void lockdebug_rwlock_assert_reading(rwlock_tt<true> *lock);
void lockdebug_rwlock_assert_writing(rwlock_tt<true> *lock);
void lockdebug_rwlock_assert_locked(rwlock_tt<true> *lock);
void lockdebug_rwlock_assert_unlocked(rwlock_tt<true> *lock);

static inline void lockdebug_remember_rwlock(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_read(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_try_read_success(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_unlock_read(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_write(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_try_write_success(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_unlock_write(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_assert_reading(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_assert_writing(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_assert_locked(rwlock_tt<false> *) { }
static inline void lockdebug_rwlock_assert_unlocked(rwlock_tt<false> *) { }

struct fork_unsafe_lock_t { };

template <bool Debug>
class rwlock_tt : nocopy_t {
private:
	pthread_rwlock_t mLock;
public:
	rwlock_tt() : mLock(PTHREAD_RWLOCK_INITIALIZER) {
		lockdebug_remember_rwlock(this);
	}
	rwlock_tt(const fork_unsafe_lock_t unsafe)
		: mLock(PTHREAD_RWLOCK_INITIALIZER) {}

	void read()
	{
		lockdebug_rwlock_read(this);

		qosStartOverride();
		int err = pthread_rwlock_rdlock(&mLock);
		if (err) _objc_fatal("pthread_rwlock_rdlock failed (%d)", err);
	}
	void unlockRead()
	{
		lockdebug_rwlock_unlock_read(this);

		int err = pthread_rwlock_unlock(&mLock);
		if (err) _objc_fatal("pthread_rwlock_unlock failed (%d)", err);
		qosEndOverride();
	}
	bool tryRead()
	{
		qosStartOverride();
		int err = pthread_rwlock_tryrdlock(&mLock);
		if (err == 0) {
			lockdebug_rwlock_try_read_success(this);
			return true;
		}
		else if (err == EBUSY) {
			qosEndOverride();
			return false;
		}
		else {
			_objc_fatal("pthread_rwlock_tryrdlock failed (%d)", err);
		}
	}
	void write()
	{
		lockdebug_rwlock_write(this);

		qosStartOverride();
		int err = pthread_rwlock_wrlock(&mLock);
		if (err) _objc_fatal("pthread_rwlock_wrlock failed (%d)", err);
	}
	void unlockWrite()
	{
		lockdebug_rwlock_unlock_write(this);

		int err = pthread_rwlock_unlock(&mLock);
		if (err) _objc_fatal("pthread_rwlock_unlock failed (%d)", err);
		qosEndOverride();
	}
	bool tryWrite()
	{
		qosStartOverride();
		int err = pthread_rwlock_trywrlock(&mLock);
		if (err == 0) {
			lockdebug_rwlock_try_write_success(this);
			return true;
		}
		else if (err == EBUSY) {
			qosEndOverride();
			return false;
		}
		else {
			_objc_fatal("pthread_rwlock_trywrlock failed (%d)", err);
		}
	}
	void forceReset()
	{
		lockdebug_rwlock_unlock_write(this);

		bzero(&mLock, sizeof(mLock));
		mLock = pthread_rwlock_t PTHREAD_RWLOCK_INITIALIZER;
	}
	void assertReading() {
		lockdebug_rwlock_assert_reading(this);
	}
	void assertWriting() {
		lockdebug_rwlock_assert_writing(this);
	}
	void assertLocked() {
		lockdebug_rwlock_assert_locked(this);
	}
	void assertUnlocked() {
		lockdebug_rwlock_assert_unlocked(this);
	}
};

// [Apple] Declarations of all locks used in the runtime.

extern rwlock_t selLock;

#endif // OBJC_LOCKS_H
