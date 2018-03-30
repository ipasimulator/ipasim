#ifndef OBJC_MAPTABLE_H
#define OBJC_MAPTABLE_H

using NXMapTable = struct _NXMapTable {
	// [Apple] Private data structure; may change.
	const struct _NXMapTablePrototype *prototype;
	unsigned count;
	unsigned nbBucketsMinusOne;
	void *buckets;
};

#endif // OBJC_MAPTABLE_H
