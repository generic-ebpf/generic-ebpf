#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <dev/ebpf/ebpf_map.h>
}

namespace {

class TommyHashtblMapDeleteTest : public ::testing::Test {
  protected:
    struct ebpf_map map;

    virtual void
    SetUp()
    {
        int error;
        uint32_t gkey = 50;
        uint32_t gval = 100;

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

TEST_F(TommyHashtblMapDeleteTest, CorrectDelete)
{
    int error;
    uint32_t key = 50;

    error = ebpf_map_delete_elem(&map, &key);

    EXPECT_EQ(0, error);
}
}
