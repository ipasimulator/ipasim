
#if defined(BUILDING_TEST)
#define IMPEXP __declspec(dllexport)
#else
#define IMPEXP __declspec(dllimport)
#endif

__attribute__((objc_root_class))
IMPEXP @interface TestClass
+ (void)initialize;
+ (void)load;
- (void)sampleMethod;
@end
