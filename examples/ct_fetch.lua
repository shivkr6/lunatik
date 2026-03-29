--
-- SPDX-FileCopyrightText: (c) 2026 Shivang <shivangraghuvanshi2005@gmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

local nf = require("netfilter")
local conntrack = require("conntrack")

local family = nf.family
local action = nf.action
local hooks = nf.inet_hooks
local priority = nf.ip_priority

local function ct_fetch_hook(skb)
	local ct, ctinfo = skb:conntrack()

	if not ct then
		return action.ACCEPT
	end

	local tuple = ct:tuple(conntrack.dir.ORIGINAL)

	local output = string.format("ct_fetch: [ctinfo=%d] src_ip=%d dst_ip=%d",
	                             ctinfo, tuple.src_ip, tuple.dst_ip)

	print(output)

	return action.ACCEPT
end

nf.register{
	hook = ct_fetch_hook,
	pf = family.IPV4,
	hooknum = hooks.LOCAL_OUT,
	priority = priority.CONNTRACK + 1,
}
