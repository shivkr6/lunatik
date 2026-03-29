/*
 * SPDX-FileCopyrightText: (c) 2026 Shivang <shivangraghuvanshi2005@gmail.com>
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 */

#ifndef luaconntrack_h
#define luaconntrack_h

#include <lunatik.h>

#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>

typedef struct luaconntrack_s {
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
} luaconntrack_t;

extern const lunatik_class_t luaconntrack_class;

#endif
