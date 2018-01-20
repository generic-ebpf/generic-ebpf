#include "ebpf_iface.h"

int
ebpf_load_prog(EBPFIface *iface, uint16_t prog_type,
    void *prog, uint32_t prog_len)
{
  return iface->load_prog(iface, prog_type, prog, prog_len);
}

int
ebpf_map_create(EBPFIface *iface, uint16_t type, uint32_t key_size,
    uint32_t value_size, uint32_t max_entries, uint32_t map_flags)
{
  return iface->map_create(iface, type, key_size, value_size,
      max_entries, map_flags);
}

int
ebpf_map_update_elem(EBPFIface *iface, int map_desc,
    void *key, void *value, uint64_t flags)
{
  return iface->map_update_elem(iface, map_desc, key, value, flags);
}

int
ebpf_map_lookup_elem(EBPFIface *iface, int map_desc,
    void *key, void *value, uint64_t flags)
{
  return iface->map_lookup_elem(iface, map_desc, key, value, flags);
}

int
ebpf_map_delete_elem(EBPFIface *iface, int map_desc, void *key)
{
  return iface->map_delete_elem(iface, map_desc, key);
}

int
ebpf_map_get_next_key(EBPFIface *iface, int map_desc,
    void *key, void *next_key)
{
  return iface->map_get_next_key(iface, map_desc, key, next_key);
}

void
ebpf_close_prog_desc(EBPFIface *iface, int prog_desc)
{
  return iface->close_prog_desc(iface, prog_desc);
}

void
ebpf_close_map_desc(EBPFIface *iface, int map_desc)
{
  return iface->close_map_desc(iface, map_desc);
}
