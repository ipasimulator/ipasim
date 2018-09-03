// cc_mapper.hpp: Contains classes `cc_mapper` and related.

#if !defined(CC_MAPPER_HPP)
#define CC_MAPPER_HPP

#include <vector>

// Represents a function signature.
class func_sig {
    // TBD.
};

enum class data_location {
    stack,
    reg_x86_ // TBD.
};

// Represents continuous data range.
class data_range {
public:
    data_range(data_location loc, size_t offset, size_t size)
        : loc_(loc), offset_(offset), size_(size) {}
    data_location get_location() const { return loc_; }
    size_t get_offset() const { return offset_; }
    size_t get_size() const { return size_; }

private:
    data_location loc_;
    size_t offset_, size_;
};

// Represents some data structure, possibly scattered across memory and registers.
class data_view {
public:
    void add_range(data_range &&range) { ranges_.push_back(std::move(range)); }
    const std::vector<data_range> get_ranges() const { return ranges_; }

private:
    std::vector<data_range> ranges_;
};

// TODO: Will const vector be able to get destructed?
using data_views = const std::vector<data_view>;

class cc_mapper {
public:
    // Maps return value (if there is any) and all arguments, in that order.
    virtual data_views map(const func_sig &sig) = 0;
};

class cc_mapper_x86 : public cc_mapper {
public:
    data_views map(const func_sig &sig) override;
};

#endif // !defined(CC_MAPPER_HPP)
