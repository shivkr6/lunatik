/*
 * SPDX-FileCopyrightText: (c) 2026 Shivang <shivangraghuvanshi2005@gmail.com>
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>

#include <lunatik.h>
#include "luaconntrack.h"

LUNATIK_PRIVATECHECKER(luaconntrack_check, luaconntrack_t *,
	luaL_argcheck(L, private->ct != NULL, ix, "conntrack is not set");
);

static int luaconntrack_status(lua_State *L)
{
	luaconntrack_t *lct = luaconntrack_check(L, 1);
	lua_pushinteger(L, lct->ct->status);
	return 1;
}

static int luaconntrack_tuple(lua_State *L)
{
	luaconntrack_t *lct = luaconntrack_check(L, 1);
	int dir = luaL_checkinteger(L, 2);

	luaL_argcheck(L, dir == IP_CT_DIR_ORIGINAL || dir == IP_CT_DIR_REPLY,
		2, "invalid direction");

	struct nf_conntrack_tuple *tuple = &lct->ct->tuplehash[dir].tuple;

	lua_newtable(L);

	lua_pushinteger(L, tuple->src.u3.ip);
	lua_setfield(L, -2, "src_ip");

	lua_pushinteger(L, tuple->dst.u3.ip);
	lua_setfield(L, -2, "dst_ip");

	lua_pushinteger(L, tuple->src.u.all);
	lua_setfield(L, -2, "src_port");

	lua_pushinteger(L, tuple->dst.u.all);
	lua_setfield(L, -2, "dst_port");

	lua_pushinteger(L, tuple->dst.protonum);
	lua_setfield(L, -2, "protonum");

	lua_pushinteger(L, tuple->src.l3num);
	lua_setfield(L, -2, "l3num");

	return 1;
}

static void luaconntrack_release(void *private)
{
	luaconntrack_t *lct = (luaconntrack_t *)private;
	lct->ct = NULL;
}

static const luaL_Reg luaconntrack_lib[] = {
	{NULL, NULL}
};

static const luaL_Reg luaconntrack_mt[] = {
	{"__gc",   lunatik_deleteobject},
	{"status", luaconntrack_status},
	{"tuple",  luaconntrack_tuple},
	{NULL, NULL}
};

static const lunatik_reg_t luaconntrack_dir[] = {
	{"ORIGINAL", IP_CT_DIR_ORIGINAL},
	{"REPLY", IP_CT_DIR_REPLY},
	{NULL, 0}
};

static const lunatik_reg_t luaconntrack_info[] = {
	{"ESTABLISHED", IP_CT_ESTABLISHED},
	{"RELATED", IP_CT_RELATED},
	{"NEW", IP_CT_NEW},
	{"IS_REPLY", IP_CT_IS_REPLY},
	{"ESTABLISHED_REPLY", IP_CT_ESTABLISHED_REPLY},
	{"RELATED_REPLY", IP_CT_RELATED_REPLY},
	{"UNTRACKED", IP_CT_UNTRACKED},
	{NULL, 0}
};

static const lunatik_reg_t luaconntrack_status_flags[] = {
	{"IPS_EXPECTED", IPS_EXPECTED},
	{"IPS_SEEN_REPLY", IPS_SEEN_REPLY},
	{"IPS_ASSURED", IPS_ASSURED},
	{"IPS_CONFIRMED", IPS_CONFIRMED},
	{"IPS_SRC_NAT", IPS_SRC_NAT},
	{"IPS_DST_NAT", IPS_DST_NAT},
	{"IPS_NAT_MASK", IPS_NAT_MASK},
	{"IPS_DYING", IPS_DYING},
	{NULL, 0}
};

static const lunatik_namespace_t luaconntrack_flags[] = {
	{"dir", luaconntrack_dir},
	{"info", luaconntrack_info},
	{"status", luaconntrack_status_flags},
	{NULL, NULL}
};

const lunatik_class_t luaconntrack_class = {
	.name    = "conntrack",
	.methods = luaconntrack_mt,
	.release = luaconntrack_release,
	.opt = LUNATIK_OPT_SOFTIRQ | LUNATIK_OPT_SINGLE,
};
EXPORT_SYMBOL(luaconntrack_class);

LUNATIK_CLASSES(conntrack, &luaconntrack_class);
LUNATIK_NEWLIB(conntrack, luaconntrack_lib, luaconntrack_classes, luaconntrack_flags);

static int __init luaconntrack_init(void)
{
	return 0;
}

static void __exit luaconntrack_exit(void)
{
}

module_init(luaconntrack_init);
module_exit(luaconntrack_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Shivang <shivangraghuvanshi2005@gmail.com>");
