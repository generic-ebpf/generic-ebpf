/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2017-2018 Yutaro Hayakawa
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

static int
bad_map_init(struct ebpf_map *self, uint32_t key_size, uint32_t value_size,
	     uint32_t max_entries, uint32_t flags)
{
	return EINVAL;
}

static int
bad_map_update_elem(struct ebpf_map *self, void *key, void *value,
		    uint64_t flags)
{
	return EINVAL;
}

static void *
bad_map_lookup_elem(struct ebpf_map *self, void *key)
{
	return NULL;
}

static int
bad_map_lookup_elem_from_user(struct ebpf_map *self, void *key, void *value)
{
	return EINVAL;
}

static int
bad_map_delete_elem(struct ebpf_map *self, void *key)
{
	return EINVAL;
}

static int
bad_map_get_next_key(struct ebpf_map *self, void *key, void *next_key)
{
	return EINVAL;
}

static void
bad_map_deinit(struct ebpf_map *self, void *arg)
{
	return;
}

struct ebpf_map_ops bad_map_ops = {.init = bad_map_init,
				   .update_elem = bad_map_update_elem,
				   .lookup_elem = bad_map_lookup_elem,
				   .delete_elem = bad_map_delete_elem,
				   .update_elem_from_user = bad_map_update_elem,
				   .lookup_elem_from_user = bad_map_lookup_elem_from_user,
				   .delete_elem_from_user = bad_map_delete_elem,
				   .get_next_key_from_user =
				       bad_map_get_next_key,
				   .deinit = bad_map_deinit};
