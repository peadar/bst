/* Copyright © 2020 Arista Networks, Inc. All rights reserved.
 *
 * Use of this source code is governed by the MIT license that can be found
 * in the LICENSE file.
 */

#include <err.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include "net.h"

int init_rtnetlink_socket()
{
	int sockfd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE);
	if (sockfd == -1) {
		err(1, "socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE");
	}
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
	};
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof (addr)) == -1) {
		err(1, "bind");
	}
	return sockfd;
}

#define nlpadding char padding_ ## __RANDOM__ [NLA_HDRLEN - sizeof (struct nlattr)]

#define nl_attr(Field) struct __attribute__((packed)) { \
		struct nlattr a; \
		nlpadding; \
		Field; \
	}

static int nl_sendmsg(int sockfd, const struct iovec *iov, size_t iovlen)
{
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
	};

	struct msghdr msg = {
		.msg_name = &addr,
		.msg_namelen = sizeof (addr),
		.msg_iov = (struct iovec *) iov,
		.msg_iovlen = iovlen,
	};

	if (sendmsg(sockfd, &msg, 0) == -1) {
		err(1, "nl_sendmsg: sendmsg");
	}

	struct {
		struct nlmsghdr hdr;
		struct nlmsgerr err;
	} resp;

	if (recv(sockfd, &resp, sizeof (resp), MSG_TRUNC) == -1) {
		err(1, "nl_sendmsg: recv");
	}

	if (resp.hdr.nlmsg_type == NLMSG_ERROR && resp.err.error != 0) {
		errno = -resp.err.error;
		return -1;
	}
	return 0;
}

void net_if_add(int sockfd, const struct nic_options *nicopts)
{
	struct nlmsghdr hdr = {
		.nlmsg_type = RTM_NEWLINK,
		.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
		.nlmsg_len = sizeof (hdr),
	};

	struct ifinfomsg ifinfo = {
		.ifi_family = 0,
	};
	hdr.nlmsg_len += sizeof (ifinfo);

	nl_attr(uint32_t ifidx) a_link = {
		.a.nla_len = NLA_HDRLEN + sizeof (a_link.ifidx),
		.a.nla_type = IFLA_LINK,
		.ifidx = nicopts->link_idx,
	};
	hdr.nlmsg_len += NLA_ALIGN(a_link.a.nla_len);

	nl_attr(char name[IF_NAMESIZE]) a_name = {
		.a.nla_len = NLA_HDRLEN + strnlen(nicopts->name, IF_NAMESIZE - 1) + 1,
		.a.nla_type = IFLA_IFNAME,
	};
	memcpy(a_name.name, nicopts->name, sizeof (a_name.name));
	hdr.nlmsg_len += NLA_ALIGN(a_name.a.nla_len);

	nl_attr(uint32_t netns) a_netns = {
		.a.nla_len = NLA_HDRLEN + sizeof (a_netns.netns),
		.a.nla_type = IFLA_NET_NS_PID,
		.netns = nicopts->netns_pid,
	};
	hdr.nlmsg_len += NLA_ALIGN(a_netns.a.nla_len);

	nl_attr() a_linkinfo = {
		.a.nla_type = NLA_F_NESTED | IFLA_LINKINFO,
	};

	nl_attr(char kind[16]) a_kind = {
		.a.nla_len = NLA_HDRLEN + strnlen(nicopts->type, 16),
		.a.nla_type = IFLA_INFO_KIND,
	};
	memcpy(a_kind.kind, nicopts->type, sizeof (a_kind.kind));

	nl_attr() a_data = {
		.a.nla_type = NLA_F_NESTED | IFLA_INFO_DATA,
	};

	nl_attr(uint32_t mode) a_mode = { .a.nla_len = 0 };
	if (strncmp(nicopts->type, "ipvlan", sizeof (nicopts->type)) == 0) {
		a_mode.a.nla_len = NLA_HDRLEN + sizeof (uint32_t);
		a_mode.a.nla_type = IFLA_IPVLAN_MODE;
		a_mode.mode = nicopts->ipvlan.mode;
	} else if (strncmp(nicopts->type, "macvlan", sizeof (nicopts->type)) == 0) {
		a_mode.a.nla_len = NLA_HDRLEN + sizeof (uint32_t);
		a_mode.a.nla_type = IFLA_MACVLAN_MODE;
		a_mode.mode = nicopts->macvlan.mode;
		if (a_mode.mode == 0) {
			a_mode.mode = MACVLAN_MODE_PRIVATE;
		}
	}

	a_data.a.nla_len = NLA_HDRLEN + NLA_ALIGN(a_mode.a.nla_len);

	a_linkinfo.a.nla_len = NLA_HDRLEN + NLA_ALIGN(a_kind.a.nla_len) + NLA_ALIGN(a_data.a.nla_len);
	hdr.nlmsg_len += NLA_ALIGN(a_linkinfo.a.nla_len);

	struct iovec iov[] = {
		{ .iov_base = &hdr,         .iov_len = sizeof (hdr) },
		{ .iov_base = &ifinfo,      .iov_len = sizeof (ifinfo) },
		{ .iov_base = &a_link,      .iov_len = NLA_ALIGN(a_link.a.nla_len) },
		{ .iov_base = &a_name,      .iov_len = NLA_ALIGN(a_name.a.nla_len) },
		{ .iov_base = &a_netns,     .iov_len = NLA_ALIGN(a_netns.a.nla_len) },
		{ .iov_base = &a_linkinfo,  .iov_len = sizeof (a_linkinfo) },
		{ .iov_base = &a_kind,      .iov_len = NLA_ALIGN(a_kind.a.nla_len) },
		{ .iov_base = &a_data,      .iov_len = sizeof (a_data) },
		{ .iov_base = &a_mode,      .iov_len = NLA_ALIGN(a_mode.a.nla_len) },
	};

	if (nl_sendmsg(sockfd, iov, sizeof (iov) / sizeof (struct iovec)) == -1) {
		err(1, "if_add %s %s", nicopts->type, nicopts->name);
	}
}

void net_if_up(int sockfd, const char *name)
{
	struct nlmsghdr hdr = {
		.nlmsg_type = RTM_NEWLINK,
		.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.nlmsg_len = sizeof (hdr),
	};

	struct ifinfomsg ifinfo = {
		.ifi_index = if_nametoindex(name),
		.ifi_flags = IFF_UP,
	};
	hdr.nlmsg_len += sizeof (ifinfo);

	struct iovec iov[] = {
		{ .iov_base = &hdr,    .iov_len = sizeof (hdr) },
		{ .iov_base = &ifinfo, .iov_len = sizeof (ifinfo) },
	};

	if (nl_sendmsg(sockfd, iov, sizeof (iov) / sizeof (struct iovec)) == -1) {
		err(1, "if_up %s", name);
	}
}

struct valmap {
	const char *name;
	void *val;
};

static int nic_parse_val(void *dst, size_t size, const struct valmap *map, const char *name)
{
	for (const struct valmap *e = &map[0]; e->name != NULL; ++e) {
		if (strcmp(name, e->name) != 0) {
			continue;
		}
		memcpy(dst, e->val, size);
		return 0;
	}
	return -1;
}

static void nic_parse_macvlan_mode(struct nic_options *nic, const char *v)
{
	struct valmap map[] = {
		{ "private",  &(uint32_t) { MACVLAN_MODE_PRIVATE  } },
		{ "vepa",     &(uint32_t) { MACVLAN_MODE_VEPA     } },
		{ "bridge",   &(uint32_t) { MACVLAN_MODE_BRIDGE   } },
		{ "passthru", &(uint32_t) { MACVLAN_MODE_PASSTHRU } },
		{ "source",   &(uint32_t) { MACVLAN_MODE_SOURCE   } },
		{ NULL, NULL },
	};
	if (nic_parse_val(&nic->macvlan.mode, sizeof (nic->macvlan.mode), map, v) == -1) {
		errx(1, "invalid MACVLAN mode %s", v);
	}
}

static void nic_parse_ipvlan_mode(struct nic_options *nic, const char *v)
{
	struct valmap map[] = {
		{ "l2",  &(uint32_t) { IPVLAN_MODE_L2  } },
		{ "l3",  &(uint32_t) { IPVLAN_MODE_L3  } },
		{ "l3s", &(uint32_t) { IPVLAN_MODE_L3S } },
		{ NULL, NULL },
	};
	if (nic_parse_val(&nic->ipvlan.mode, sizeof (nic->ipvlan.mode), map, v) == -1) {
		errx(1, "invalid IPVLAN mode %s", v);
	}
}

static void nic_parse_link(struct nic_options *nic, const char *v)
{
	nic->link_idx = if_nametoindex(v);
	if (nic->link_idx == 0) {
		err(1, "if_nametoindex %s", v);
	}
}

void nic_parse(struct nic_options *nic, const char *key, const char *val)
{
	struct optmap {
		const char *nictype;
		const char *opt;
		void (*fn)(struct nic_options *, const char *);
	};

	static struct optmap opts[] = {
		{ "macvlan", "mode", nic_parse_macvlan_mode },
		{ "macvlan", "link", nic_parse_link },
		{ "ipvlan",  "mode", nic_parse_ipvlan_mode  },
		{ "ipvlan",  "link", nic_parse_link },
		{ NULL, NULL, NULL },
	};

	for (struct optmap *e = &opts[0]; e->nictype != NULL; ++e) {
		if (strncmp(nic->type, e->nictype, sizeof (nic->type)) != 0) {
			continue;
		}
		if (strcmp(key, e->opt) != 0) {
			continue;
		}
		e->fn(nic, val);
		return;
	}
	errx(1, "unknown option '%s' for interface type '%s'", key, nic->type);
}
