enum ebpf_ds_type { LIST };

struct ebpf_ds_def {
    enum ebpf_ds_type type;
    unsigned long long key_size;
    unsigned long long val_size;
};

#define SEC(sec_name) __attribute__((section(sec_name)))

struct ebpf_ds_def SEC("ds") ds1 = {
    .type = LIST, .key_size = 100, .val_size = 100};

struct ebpf_ds_def SEC("ds") ds2 = {
    .type = LIST, .key_size = 100, .val_size = 100};

int
test(int a)
{
    return a;
}
