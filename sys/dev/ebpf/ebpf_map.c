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

const struct ebpf_map_type *ebpf_map_types[] = {
	[EBPF_MAP_TYPE_BAD]              = &bad_map_type,
	[EBPF_MAP_TYPE_ARRAY]            = &array_map_type,
	[EBPF_MAP_TYPE_PERCPU_ARRAY]     = &percpu_array_map_type,
	[EBPF_MAP_TYPE_HASHTABLE]        = &hashtable_map_type,
	[EBPF_MAP_TYPE_PERCPU_HASHTABLE] = &percpu_hashtable_map_type
};

#define EBPF_MAP_TYPE_OPS(_type) (ebpf_map_types[_type]->ops)

const struct ebpf_map_type *
ebpf_get_map_type(uint16_t type)
{
	if (type >= EBPF_MAP_TYPE_MAX) {
		return NULL;
	}

	return ebpf_map_types[type];
}

static void
ebpf_map_dtor(struct ebpf_obj *eo)
{
	struct ebpf_obj_map *eom = (struct ebpf_obj_map *)eo;
	EBPF_MAP_TYPE_OPS(eom->type).deinit(eom);
}

int
ebpf_map_create(struct ebpf_obj_map **eomp, struct ebpf_map_attr *attr)
{
	int error;
	struct ebpf_obj_map *eom;

	if (eomp == NULL || attr == NULL ||
			attr->type >= EBPF_MAP_TYPE_MAX ||
			attr->key_size == 0 || attr->value_size == 0 ||
			attr->max_entries == 0)
		return EINVAL;

	eom = ebpf_malloc(sizeof(*eom));
	if (eom == NULL)
		return ENOMEM;

	ebpf_refcount_init(&eom->eo.ref, 1);
	eom->eo.type		= EBPF_OBJ_TYPE_MAP;
	eom->eo.dtor		= ebpf_map_dtor;
	eom->type		= attr->type;
	eom->key_size		= attr->key_size;
	eom->value_size		= attr->value_size;
	eom->max_entries	= attr->max_entries;
	eom->map_flags		= attr->flags;

	error = EBPF_MAP_TYPE_OPS(attr->type).init(eom, attr);
	if (error != 0) {
		ebpf_free(eom);
		return error;
	}

	*eomp = eom;

	return 0;
}

void *
ebpf_map_lookup_elem(struct ebpf_obj_map *eom, void *key)
{
	if (eom == NULL || key == NULL) {
		return NULL;
	}

	return EBPF_MAP_TYPE_OPS(eom->type).lookup_elem(eom, key);
}

int
ebpf_map_lookup_elem_from_user(struct ebpf_obj_map *eom, void *key, void *value)
{
	int error;

	if (eom == NULL || key == NULL || value == NULL) {
		return EINVAL;
	}

	ebpf_epoch_enter();
	error = EBPF_MAP_TYPE_OPS(eom->type).lookup_elem_from_user(eom, key, value);
	ebpf_epoch_exit();

	return error;
}

int
ebpf_map_update_elem(struct ebpf_obj_map *eom, void *key, void *value,
		     uint64_t flags)
{
	if (eom == NULL || key == NULL ||
			value == NULL || flags > EBPF_EXIST) {
		return EINVAL;
	}

	return EBPF_MAP_TYPE_OPS(eom->type).update_elem(eom, key, value, flags);
}

int
ebpf_map_update_elem_from_user(struct ebpf_obj_map *eom, void *key, void *value,
			       uint64_t flags)
{
	int error;

	ebpf_epoch_enter();
	error = EBPF_MAP_TYPE_OPS(eom->type).update_elem_from_user(eom, key, value, flags);
	ebpf_epoch_exit();

	return error;
}

int
ebpf_map_delete_elem(struct ebpf_obj_map *eom, void *key)
{
	if (eom == NULL || key == NULL) {
		return EINVAL;
	}

	return EBPF_MAP_TYPE_OPS(eom->type).delete_elem(eom, key);
}

int
ebpf_map_delete_elem_from_user(struct ebpf_obj_map *eom, void *key)
{
	int error;
	if (eom == NULL || key == NULL) {
		return EINVAL;
	}

	ebpf_epoch_enter();
	error = EBPF_MAP_TYPE_OPS(eom->type).delete_elem_from_user(eom, key);
	ebpf_epoch_exit();

	return error;
}

int
ebpf_map_get_next_key_from_user(struct ebpf_obj_map *eom, void *key, void *next_key)
{
	int error;

	/*
	 * key == NULL is valid, because it means "Give me a
	 * first key"
	 */
	if (eom == NULL || next_key == NULL) {
		return EINVAL;
	}

	ebpf_epoch_enter();
	error = EBPF_MAP_TYPE_OPS(eom->type).get_next_key_from_user(eom, key, next_key);
	ebpf_epoch_exit();

	return error;
}

void
ebpf_map_destroy(struct ebpf_obj_map *eom)
{
	if (eom == NULL)
		return;

	ebpf_obj_release(&eom->eo);
}
