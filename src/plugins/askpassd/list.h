/*
 * Copyright (c) 2015 Red Hat, Inc.
 * Author: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once
#include <stddef.h>

#define align_as(t) __attribute__ ((aligned(__alignof__(t))))

struct list {
    struct list *prev;
    struct list *next;
};

#define LIST(name) struct list name = LIST_INIT(name)
#define LIST_INIT(name) (struct list) { &(name), &(name) }
#define LIST_ITEM(item, type, member) ({ \
    (type *) ((void *) (item) - offsetof(type, member)); \
})

#define LIST_EMPTY(list) ((list)->prev == (list) && (list)->next == (list))

#define LIST_FOREACH(list, type, name, member) \
    for (type *__lst = LIST_ITEM(list, type, member), \
              *name  = LIST_ITEM(__lst->member.next, type, member), \
              *__nxt = LIST_ITEM(name->member.next, type, member); \
               name != __lst; name = __nxt, \
              __nxt  = LIST_ITEM(name->member.next, type, member))

void
list_add_after(struct list *list, struct list *item);

struct list *
list_pop(struct list *item);
