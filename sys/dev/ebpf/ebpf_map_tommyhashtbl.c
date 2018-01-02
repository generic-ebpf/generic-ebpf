/*
 * Copyright 2017 Yutaro Hayakawa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ebpf_map.h"
#include "tommyds/tommyhashtbl.h"

struct ebpf_map_tommyhashtbl {
  tommy_hashtable table;
};

struct ebpf_map_tommyhashtbl_elem {
  void *key;
  void *value;
  struct ebpf_map *map;
  tommy_hashtable_node node;
};

static void
tommyhashtbl_map_release_elem(void *obj)
{
  struct ebpf_map_tommyhashtbl_elem *elem = (struct ebpf_map_tommyhashtbl_elem *)obj;

  ebpf_free(elem->key);
  ebpf_free(elem->value);
  ebpf_free(elem);
}

static int
tommyhashtbl_map_cmp(const void *a, const void *b)
{
    const struct ebpf_map_tommyhashtbl_elem *elem = 
      (const struct ebpf_map_tommyhashtbl_elem *)b;
    return memcmp(a, elem->key, elem->map->key_size);
}

static int
tommyhashtbl_map_init(struct ebpf_map *self, uint16_t key_size, uint16_t value_size, uint16_t max_entries, uint32_t flags)
{
    self->type = EBPF_MAP_TYPE_TOMMYHASHTBL;
    self->key_size = key_size;
    self->value_size = value_size;
    self->max_entries = max_entries;
    self->map_flags = flags;

    struct ebpf_map_tommyhashtbl *new = ebpf_calloc(sizeof(struct ebpf_map_tommyhashtbl), 1);
    if (!new) {
        return ENOMEM;
    }

    tommy_hashtable_init(&new->table, max_entries);
    self->data = new;

    return 0;
}

static int
tommyhashtbl_map_update_elem(struct ebpf_map *self, void *key, void *value, uint64_t flags)
{
    struct ebpf_map_tommyhashtbl *map = (struct ebpf_map_tommyhashtbl *)self->data;

    if (tommy_hashtable_count(&map->table) == self->max_entries - 1) {
        return EBUSY;
    }

    void *k = ebpf_calloc(self->key_size, 1);
    if (!k) {
        return ENOMEM;
    }
    memcpy(k, key, self->key_size);

    void *v = ebpf_calloc(self->value_size, 1);
    if (!v) {
        ebpf_free(k);
        return ENOMEM;
    }
    memcpy(v, value, self->value_size);

    struct ebpf_map_tommyhashtbl_elem *elem =
      ebpf_calloc(sizeof(struct ebpf_map_tommyhashtbl_elem), 1);
    if (!elem) {
        ebpf_free(k);
        ebpf_free(v);
        return ENOMEM;
    }

    elem->key = k;
    elem->value = v;
    elem->map = self;

    tommy_hashtable_insert(&map->table, &elem->node, elem,
        tommy_hash_u64(0, k, self->key_size));

    return 0;
}

static void *
tommyhashtbl_map_lookup_elem(struct ebpf_map *self, void *key, uint64_t flags)
{
    struct ebpf_map_tommyhashtbl *map = (struct ebpf_map_tommyhashtbl *)self->data;

    if (tommy_hashtable_count(&map->table) == 0) {
        return NULL;
    }

    struct ebpf_map_tommyhashtbl_elem *elem = tommy_hashtable_search(&map->table,
        tommyhashtbl_map_cmp, key, tommy_hash_u64(0, key, self->key_size));

    if (!elem) {
      return NULL;
    }

    return elem->value;
}

static int
tommyhashtbl_map_delete_elem(struct ebpf_map *self, void *key)
{
    struct ebpf_map_tommyhashtbl *map = (struct ebpf_map_tommyhashtbl *)self->data;

    if (tommy_hashtable_count(&map->table) == 0) {
        return ENOENT;
    }

    struct ebpf_map_tommyhashtbl_elem *elem = tommy_hashtable_remove(&map->table,
        tommyhashtbl_map_cmp, key, tommy_hash_u64(0, key, self->key_size));
    if (elem == 0) {
        return ENOENT;
    }

    ebpf_free(elem->key);
    ebpf_free(elem->value);
    ebpf_free(elem);

    return 0;
}

static int
tommyhashtbl_map_get_next_key(struct ebpf_map *self, void *key, void *next_key)
{
    int pos = 0, cur;
    struct ebpf_map_tommyhashtbl *map = (struct ebpf_map_tommyhashtbl *)self->data;
    tommy_hashtable *table = &map->table;

    if (tommy_hashtable_count(table) == 0 ||
        (tommy_hashtable_count(table) == 1 && key != NULL)) {
        return ENOENT;
    }

    if (key == NULL) {
        goto get_first_key;
    }

    tommy_hashtable_node *node = tommy_hashtable_bucket(&map->table, tommy_hash_u64(0, key, self->key_size));
    if (node->next == 0) {
        pos = node->key & table->bucket_mask;
        if (pos == table->bucket_max - 1) {
            pos = 0;
        } else {
            pos = pos + 1;
        }
        goto get_first_key;
    }

    node = node->next;
    struct ebpf_map_tommyhashtbl_elem *elem = (struct ebpf_map_tommyhashtbl_elem *)node->data;
    memcpy(next_key, elem->key, self->key_size);

    return 0;

get_first_key:
    for (int i = pos; i < table->bucket_max + pos; i++) {
        cur = i % table->bucket_max;
        if (table->bucket[cur]) {
            struct ebpf_map_tommyhashtbl_elem *elem = (struct ebpf_map_tommyhashtbl_elem *)table->bucket[cur]->data;
            memcpy(next_key, elem->key, self->key_size);
            break;
        }
    }

    return 0;
}

static void
tommyhashtbl_map_deinit(struct ebpf_map *self, void *arg)
{
    struct ebpf_map_tommyhashtbl *map = (struct ebpf_map_tommyhashtbl *)self->data;

    tommy_hashtable_foreach(&map->table, tommyhashtbl_map_release_elem);

    tommy_hashtable_done(&map->table);
    ebpf_free(map);
}

const struct ebpf_map_ops tommyhashtbl_map_ops = {
    .init = tommyhashtbl_map_init,
    .update_elem = tommyhashtbl_map_update_elem,
    .lookup_elem = tommyhashtbl_map_lookup_elem,
    .delete_elem = tommyhashtbl_map_delete_elem,
    .get_next_key = tommyhashtbl_map_get_next_key,
    .deinit = tommyhashtbl_map_deinit
};
