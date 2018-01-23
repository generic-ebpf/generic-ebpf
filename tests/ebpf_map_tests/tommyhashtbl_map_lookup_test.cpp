#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <dev/ebpf/ebpf_map.h>
}

namespace {
class TommyHashtblMapLookupTest : public ::testing::Test {
  protected:
    struct ebpf_map map;

    virtual void
    SetUp()
    {
        int error;
        uint32_t gkey = 50, gval = 100;

        error = ebpf_map_init(&map, EBPF_MAP_TYPE_TOMMYHASHTBL,
                              sizeof(uint32_t), sizeof(uint32_t), 100, 0);
        assert(!error);

        error = ebpf_map_update_elem(&map, &gkey, &gval, 0);
        assert(!error);
    }

    virtual void
    TearDown()
    {
        ebpf_map_deinit(&map, NULL);
    }
};

TEST_F(TommyHashtblMapLookupTest, LookupUnexistingEntry)
{
    int error;
    uint32_t key = 51;
    void *value;

    value = ebpf_map_lookup_elem(&map, &key, 0);

    EXPECT_EQ(NULL, value);
}

TEST_F(TommyHashtblMapLookupTest, CorrectLookup)
{
    int error;
    uint32_t key = 50;
    uint32_t *value;

    value = (uint32_t *)ebpf_map_lookup_elem(&map, &key, 0);

    EXPECT_EQ(100, *value);
}
}
