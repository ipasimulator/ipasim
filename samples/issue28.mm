// See i28.

struct BigStr {
    int One;
    int Two;
    int Three;
    int Four;
    int Five;
    int Six;
};

struct SmallStr {
    int One;
    int Two;
};

@interface MyCls
+ (BigStr)getMeBigStr;
+ (SmallStr)getMeSmallStr;
@end

@implementation MyCls
+ (BigStr)getMeBigStr {
    return BigStr{1,2,3,4,5,6};
}
+ (SmallStr)getMeSmallStr {
    return SmallStr{1,2};
}
@end

int main() {
    BigStr BS([MyCls getMeBigStr]);
    SmallStr SS([MyCls getMeSmallStr]);
    return BS.Six + SS.Two;
}
