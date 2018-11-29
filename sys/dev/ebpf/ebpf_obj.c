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

#include "ebpf_obj.h"

int
ebpf_obj_type_init(struct ebpf_obj_type *type)
{
	if (type == NULL) {
		return EINVAL;
	}

	ebpf_refcount_init(&type->eot_refcount, 0);

	return 0;
}

int
ebpf_obj_type_registry_init(struct ebpf_obj_type_registry *registry)
{
	if (registry == NULL) {
		return EINVAL;
	}

	memset(registry, 0, sizeof(*registry));
	ebpf_mtx_init(&registry->mtx, "ebpf_obj_type_registry_lock");

	return 0;
}

int
ebpf_obj_type_register(struct ebpf_obj_type_registry *registry,
		struct ebpf_obj_type *type, uint16_t *idxp)
{
	int error = 0;

	if (registry == NULL || type == NULL || idxp == NULL) {
		return EINVAL;
	}

	ebpf_mtx_lock(&registry->mtx);

	/*
	 * Find the available slot
	 */
	uint16_t avail_idx = EBPF_TYPE_MAX;
	for (uint16_t i = 0; i < EBPF_TYPE_MAX; i++) {
		/* Won't break early to find duplicated entry */
		if (avail_idx == EBPF_TYPE_MAX &&
				registry->types[i] == NULL) {
			avail_idx = i;
		}

		/* Find duplicated entry, return error */
		if (registry->types[i] == type) {
			error = EEXIST;
			goto err0;
		}
	}

	if (avail_idx == EBPF_TYPE_MAX) {
		error = EBUSY;
		goto err0;
	}

	*idxp = avail_idx;
	registry->types[avail_idx] = type;
	ebpf_refcount_acquire(&type->eot_refcount);

err0:
	ebpf_mtx_unlock(&registry->mtx);
	return error;
}

int
ebpf_obj_type_unregister(struct ebpf_obj_type_registry *registry, uint16_t idx)
{
	int error = 0;

	if (registry == NULL || idx >= EBPF_TYPE_MAX) {
		return EINVAL;
	}

	ebpf_mtx_lock(&registry->mtx);

	if (registry->types[idx] == NULL) {
		error = ENOENT;
		goto err0;
	}

	ebpf_refcount_release(&registry->types[idx]->eot_refcount);
	registry->types[idx] = NULL;

err0:
	ebpf_mtx_unlock(&registry->mtx);
	return 0;
}

int
ebpf_obj_type_acquire(struct ebpf_obj_type_registry *registry, uint16_t idx,
		struct ebpf_obj_type **typep)
{
	if (registry == NULL || idx >= EBPF_TYPE_MAX || typep == NULL) {
		return EINVAL;
	}

	if (registry->types[idx] == NULL) {
		return ENOENT;
	}

	ebpf_refcount_acquire(&registry->types[idx]->eot_refcount);
	*typep = registry->types[idx];

	return 0;
}

int
ebpf_obj_type_release(struct ebpf_obj_type *type)
{
	if (type == NULL) {
		return EINVAL;
	}

	ebpf_refcount_release(&type->eot_refcount);

	return 0;
}

int
ebpf_obj_type_lookup(struct ebpf_obj_type_registry *registry,
		const char *name, uint16_t *idxp)
{
	if (registry == NULL || name == NULL) {
		return EINVAL;
	}

	for (uint16_t i = 0; i < EBPF_TYPE_MAX; i++) {
		if (strcmp(registry->types[i]->eot_name, name) == 0) {
			*idxp = i;
			return 0;
		}
	}

	return ENOENT;
}
