/*-
 * Copyright (c) 2008 Paolo Pisati
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>


#include <sys/param.h>
//#include <sys/systm.h>
//#include <sys/eventhandler.h>
#include <sys/malloc.h>
//#include <sys/kernel.h>
#include <sys/mbuf.h>
//#include <sys/lock.h>
//#include <sys/module.h>
//#include <sys/rwlock.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#define        IPFW_INTERNAL   /* Access to protected data structures in ip_fw.h. */

#include "alias.h"
#include "alias_local.h"

//#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_fw.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/route.h>
#include <net/if.h>
#include <netdb.h>
#include "ip_fw_private.h"
#include "ipfw2.h"

#define IPFW_WUNLOCK(c)
#define IPFW_WLOCK(c)
#define IPFW_RLOCK(c)
#define IPFW_RUNLOCK(c)
#define IPFW_WLOCK_ASSERT(c)

extern struct ip_fw_chain layer3_chain;
/*
 * Structure of a Link-Level sockaddr:
 */
struct sockaddr_dl {
	u_char  sdl_len;        /* Total length of sockaddr */
	u_char  sdl_family;     /* AF_LINK */
	u_short sdl_index;      /* if != 0, system given index for interface */
	u_char  sdl_type;       /* interface type */
	u_char  sdl_nlen;       /* interface name length, no trailing 0 reqd. */
	u_char  sdl_alen;       /* link level address length */
	u_char  sdl_slen;       /* link layer selector length */
	char    sdl_data[46];   /* minimum work area, can be larger;
			       contains both if name and ll address */
};
#define SA_SIZE(sa)                                             \
  (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?      \
           sizeof(long)            :                               \
           1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )

/*
 * delete the pointers for nat entry ix, or all of them if ix < 0
 */
static void
flush_nat_ptrs(struct ip_fw_chain *chain, const int ix)
{
	int i;
	ipfw_insn_nat *cmd;

	IPFW_WLOCK_ASSERT(chain);
	for (i = 0; i < chain->n_rules; i++) {
		cmd = (ipfw_insn_nat *)ACTION_PTR(chain->map[i]);
		/* XXX skip log and the like ? */
		if (cmd->o.opcode == O_NAT && cmd->nat != NULL &&
			    (ix < 0 || cmd->nat->id == ix))
			cmd->nat = NULL;
	}
}

static int
add_redir_spool_cfg(char *buf, struct cfg_nat *ptr)
{
	struct cfg_redir *r, *ser_r;
	struct cfg_spool *s, *ser_s;
	int cnt, off, i;

	for (cnt = 0, off = 0; cnt < ptr->redir_cnt; cnt++) {
		ser_r = (struct cfg_redir *)&buf[off];
		r = malloc(SOF_REDIR, M_IPFW, M_WAITOK | M_ZERO);
		memcpy(r, ser_r, SOF_REDIR);
		LIST_INIT(&r->spool_chain);
		off += SOF_REDIR;
		r->alink = malloc(sizeof(struct alias_link *) * r->pport_cnt,
		    M_IPFW, M_WAITOK | M_ZERO);
		switch (r->mode) {
		case REDIR_ADDR:
			r->alink[0] = LibAliasRedirectAddr(ptr->lib, r->laddr,
			    r->paddr);
			break;
		case REDIR_PORT:
			for (i = 0 ; i < r->pport_cnt; i++) {
				/* If remotePort is all ports, set it to 0. */
				u_short remotePortCopy = r->rport + i;
				if (r->rport_cnt == 1 && r->rport == 0)
					remotePortCopy = 0;
				r->alink[i] = LibAliasRedirectPort(ptr->lib,
				    r->laddr, htons(r->lport + i), r->raddr,
				    htons(remotePortCopy), r->paddr,
				    htons(r->pport + i), r->proto);
				if (r->alink[i] == NULL) {
					r->alink[0] = NULL;
					break;
				}
			}
			break;
		case REDIR_PROTO:
			r->alink[0] = LibAliasRedirectProto(ptr->lib ,r->laddr,
			    r->raddr, r->paddr, r->proto);
			break;
		default:
			printf("unknown redirect mode: %u\n", r->mode);
			break;
		}
		/* XXX perhaps return an error instead of panic ? */
		if (r->alink[0] == NULL)
			panic("LibAliasRedirect* returned NULL");
		/* LSNAT handling. */
		for (i = 0; i < r->spool_cnt; i++) {
			ser_s = (struct cfg_spool *)&buf[off];
			s = malloc(SOF_REDIR, M_IPFW, M_WAITOK | M_ZERO);
			memcpy(s, ser_s, SOF_SPOOL);
			LibAliasAddServer(ptr->lib, r->alink[0],
			    s->addr, htons(s->port));
			off += SOF_SPOOL;
			/* Hook spool entry. */
			LIST_INSERT_HEAD(&r->spool_chain, s, _next);
		}
		/* And finally hook this redir entry. */
		LIST_INSERT_HEAD(&ptr->redir_chain, r, _next);
	}
	return (1);
}

static int
ipfw_nat( struct ifnet * oif_arg, struct cfg_nat *t, struct mbuf *m)
{
	struct mbuf *mcl = m;
	struct ip *ip;
	/* XXX - libalias duct tape */
	int ldt, retval;
	char *c;

	ldt = 0;
	retval = 0;
	//mcl = m_megapullup(m, m->m_pkthdr.len);
	/*mcl = m_dup(m, M_WAITOK);
	if (mcl == NULL) {
		m = NULL;
		return (IP_FW_DENY);
	}*/
	ip = mtod(mcl, struct ip *);

	/*
	 * XXX - Libalias checksum offload 'duct tape':
	 *
	 * locally generated packets have only pseudo-header checksum
	 * calculated and libalias will break it[1], so mark them for
	 * later fix.  Moreover there are cases when libalias modifies
	 * tcp packet data[2], mark them for later fix too.
	 *
	 * [1] libalias was never meant to run in kernel, so it does
	 * not have any knowledge about checksum offloading, and
	 * expects a packet with a full internet checksum.
	 * Unfortunately, packets generated locally will have just the
	 * pseudo header calculated, and when libalias tries to adjust
	 * the checksum it will actually compute a wrong value.
	 *
	 * [2] when libalias modifies tcp's data content, full TCP
	 * checksum has to be recomputed: the problem is that
	 * libalias does not have any idea about checksum offloading.
	 * To work around this, we do not do checksumming in LibAlias,
	 * but only mark the packets in th_x2 field. If we receive a
	 * marked packet, we calculate correct checksum for it
	 * aware of offloading.  Why such a terrible hack instead of
	 * recalculating checksum for each packet?
	 * Because the previous checksum was not checked!
	 * Recalculating checksums for EVERY packet will hide ALL
	 * transmission errors. Yes, marked packets still suffer from
	 * this problem. But, sigh, natd(8) has this problem, too.
	 *
	 * TODO: -make libalias mbuf aware (so
	 * it can handle delayed checksum and tso)
	 */

	if (mcl->m_pkthdr.rcvif == NULL &&
	    mcl->m_pkthdr.csum_flags & CSUM_DELAY_DATA)
		ldt = 1;

	c = mtod(mcl, char *);

	if (oif_arg == NULL)
		retval = LibAliasIn(t->lib, c,
			mcl->m_len + M_TRAILINGSPACE(mcl));
	else
		retval = LibAliasOut(t->lib, c,
			mcl->m_len + M_TRAILINGSPACE(mcl));
	if (retval == PKT_ALIAS_RESPOND) {
		m->m_flags |= M_SKIP_FIREWALL;
		retval = PKT_ALIAS_OK;
	}
	if (retval != PKT_ALIAS_OK &&
	    retval != PKT_ALIAS_FOUND_HEADER_FRAGMENT) {
		/* XXX - should i add some logging? */
		m_free(mcl);
		m = NULL;
		return (IP_FW_DENY);
	}
	mcl->m_pkthdr.len = mcl->m_len = ntohs(ip->ip_len);

	/*
	 * XXX - libalias checksum offload
	 * 'duct tape' (see above)
	 */

	if ((ip->ip_off & htons(IP_OFFMASK)) == 0 &&
	    ip->ip_p == IPPROTO_TCP) {
		struct tcphdr 	*th;

		th = (struct tcphdr *)(ip + 1);
		if (th->th_x2)
			ldt = 1;
	}

	if (ldt) {
		struct tcphdr 	*th;
		struct udphdr 	*uh;
		u_short cksum;

		/* XXX check if ip_len can stay in net format */
		cksum = in_pseudo(
		    ip->ip_src.s_addr,
		    ip->ip_dst.s_addr,
		    htons(ip->ip_p + ntohs(ip->ip_len) - (ip->ip_hl << 2))
		);

		switch (ip->ip_p) {
		case IPPROTO_TCP:
			th = (struct tcphdr *)(ip + 1);
			/*
			 * Maybe it was set in
			 * libalias...
			 */
			th->th_x2 = 0;
			th->th_sum = cksum;
			mcl->m_pkthdr.csum_data =
			    offsetof(struct tcphdr, th_sum);
			break;
		case IPPROTO_UDP:
			uh = (struct udphdr *)(ip + 1);
			uh->uh_sum = cksum;
			mcl->m_pkthdr.csum_data =
			    offsetof(struct udphdr, uh_sum);
			break;
		}
		/* No hw checksum offloading: do it ourselves */
		if ((mcl->m_pkthdr.csum_flags & CSUM_DELAY_DATA) == 0) {
			in_delayed_cksum(mcl);
			mcl->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA;
		}
	}
	return (IP_FW_NAT);
}

static struct cfg_nat *
lookup_nat(struct nat_list *l, int nat_id)
{
	struct cfg_nat *res;

	LIST_FOREACH(res, l, _next) {
		if (res->id == nat_id)
			break;
	}
	return res;
}

static int
ipfw_nat_cfg(struct sockopt *sopt)
{
	struct cfg_nat *ptr, *ser_n;
	char *buf;
	struct ip_fw_chain *chain = &layer3_chain;

	buf = malloc(NAT_BUF_LEN, M_IPFW, M_WAITOK | M_ZERO);
	sooptcopyin(sopt, buf, NAT_BUF_LEN, sizeof(struct cfg_nat));
	ser_n = (struct cfg_nat *)buf;

	/* check valid parameter ser_n->id > 0 ? */
	/*
	 * Find/create nat rule.
	 */
	IPFW_WLOCK(chain);
	ptr = lookup_nat(&chain->nat, ser_n->id);
	if (ptr == NULL) {
		/* New rule: allocate and init new instance. */
		ptr = malloc(sizeof(struct cfg_nat),
		    M_IPFW, M_NOWAIT | M_ZERO);
		if (ptr == NULL) {
			IPFW_WUNLOCK(chain);
			free(buf, M_IPFW);
			return (ENOSPC);
		}
		ptr->lib = LibAliasInit(NULL);
		if (ptr->lib == NULL) {
			IPFW_WUNLOCK(chain);
			free(ptr, M_IPFW);
			free(buf, M_IPFW);
			return (EINVAL);
		}
		LIST_INIT(&ptr->redir_chain);
	} else {
		/* Entry already present: temporarly unhook it. */
		LIST_REMOVE(ptr, _next);
		flush_nat_ptrs(chain, ser_n->id);
	}
	IPFW_WUNLOCK(chain);

	/*
	 * Basic nat configuration.
	 */
	ptr->id = ser_n->id;
	/*
	 * XXX - what if this rule doesn't nat any ip and just
	 * redirect?
	 * do we set aliasaddress to 0.0.0.0?
	 */
	ptr->ip = ser_n->ip;
	ptr->redir_cnt = ser_n->redir_cnt;
	ptr->mode = ser_n->mode;
	LibAliasSetMode(ptr->lib, ser_n->mode, ser_n->mode);
	LibAliasSetAddress(ptr->lib, ptr->ip);
	memcpy(ptr->if_name, ser_n->if_name, IF_NAMESIZE);

	/*
	 * Redir and LSNAT configuration.
	 */
	/* Delete old cfgs. */
	//del_redir_spool_cfg(ptr, &ptr->redir_chain);
	/* Add new entries. */
	add_redir_spool_cfg(&buf[(sizeof(struct cfg_nat))], ptr);
	free(buf, M_IPFW);
	IPFW_WLOCK(chain);
	LIST_INSERT_HEAD(&chain->nat, ptr, _next);
	IPFW_WUNLOCK(chain);
	return (0);
}


static int
ipfw_nat_get_cfg(struct sockopt *sopt)
{
	uint8_t *data;
	struct cfg_nat *n;
	struct cfg_redir *r;
	struct cfg_spool *s;
	int nat_cnt, off;
	struct ip_fw_chain *chain;
	int err = ENOSPC;

	chain = &layer3_chain;
	nat_cnt = 0;
	off = sizeof(nat_cnt);

	data = malloc(NAT_BUF_LEN, M_IPFW, M_WAITOK | M_ZERO);
	IPFW_RLOCK(chain);
	/* Serialize all the data. */
	LIST_FOREACH(n, &chain->nat, _next) {
		nat_cnt++;
		if (off + SOF_NAT >= NAT_BUF_LEN)
			goto nospace;
		bcopy(n, &data[off], SOF_NAT);
		off += SOF_NAT;
		LIST_FOREACH(r, &n->redir_chain, _next) {
			if (off + SOF_REDIR >= NAT_BUF_LEN)
				goto nospace;
			bcopy(r, &data[off], SOF_REDIR);
			off += SOF_REDIR;
			LIST_FOREACH(s, &r->spool_chain, _next) {
				if (off + SOF_SPOOL >= NAT_BUF_LEN)
					goto nospace;
				bcopy(s, &data[off], SOF_SPOOL);
				off += SOF_SPOOL;
			}
		}
	}
	err = 0; /* all good */
nospace:
	IPFW_RUNLOCK(chain);
	if (err == 0) {
		bcopy(&nat_cnt, data, sizeof(nat_cnt));
		sooptcopyout(sopt, data, NAT_BUF_LEN);
	} else {
		printf("serialized data buffer not big enough:"
		    "please increase NAT_BUF_LEN\n");
	}
	free(data, M_IPFW);
	return (err);
}



void
ipfw_nat_init(void)
{

	IPFW_WLOCK(&layer3_chain);
	/* init ipfw hooks */
	ipfw_nat_ptr = ipfw_nat;
	lookup_nat_ptr = lookup_nat;
	ipfw_nat_cfg_ptr = ipfw_nat_cfg;
	
	ipfw_nat_get_cfg_ptr = ipfw_nat_get_cfg;
	
	IPFW_WUNLOCK(&layer3_chain);
	/*V_ifaddr_event_tag = EVENTHANDLER_REGISTER(
	    ifaddr_event, ifaddr_change,
	    NULL, EVENTHANDLER_PRI_ANY);*/
}



/* end of file */


static struct _s_x nat_params[] = {
	{ "ip",	                TOK_IP },
	{ "if",	                TOK_IF },
 	{ "log",                TOK_ALOG },
 	{ "deny_in",	        TOK_DENY_INC },
 	{ "same_ports",	        TOK_SAME_PORTS },
 	{ "unreg_only",	        TOK_UNREG_ONLY },
 	{ "reset",	        TOK_RESET_ADDR },
 	{ "reverse",	        TOK_ALIAS_REV },
 	{ "proxy_only",	        TOK_PROXY_ONLY },
	{ "redirect_addr",	TOK_REDIR_ADDR },
	{ "redirect_port",	TOK_REDIR_PORT },
	{ "redirect_proto",	TOK_REDIR_PROTO },
 	{ NULL, 0 }	/* terminator */
};


/*
 * Search for interface with name "ifn", and fill n accordingly:
 *
 * n->ip        ip address of interface "ifn"
 * n->if_name   copy of interface name "ifn"
 */
static void
set_addr_dynamic(const char *ifn, struct cfg_nat *n)
{
	size_t needed;
	int mib[6];
	char *buf, *lim, *next;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;
	struct sockaddr_dl *sdl;
	struct sockaddr_in *sin;
	int ifIndex, ifMTU;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;
/*
 * Get interface data.
 */

	int res = sysctl(mib, 6, NULL, &needed, NULL, 0);
		
	buf = safe_calloc(1, needed);
	res = sysctl(mib, 6, buf, &needed, NULL, 0);
	lim = buf + needed;

/*
 * Loop through interfaces until one with
 * given name is found. This is done to
 * find correct interface index for routing
 * message processing.
 */
	ifIndex	= 0;
	next = buf;
	while (next < lim) {
		ifm = (struct if_msghdr *)next;
		next += ifm->ifm_msglen;
		if (ifm->ifm_version != RTM_VERSION) {
			
			continue;
		}
		if (ifm->ifm_type == RTM_IFINFO) {
			sdl = (struct sockaddr_dl *)(ifm + 1);
			if (strlen(ifn) == sdl->sdl_nlen &&
			    strncmp(ifn, sdl->sdl_data, sdl->sdl_nlen) == 0) {
				ifIndex = ifm->ifm_index;
				ifMTU = ifm->ifm_data.ifi_mtu;
				break;
			}
		}
	}
	if (!ifIndex)
		errx(1, "unknown interface name %s", ifn);
/*
 * Get interface address.
 */
	sin = NULL;
	while (next < lim) {
		ifam = (struct ifa_msghdr *)next;
		next += ifam->ifam_msglen;
		if (ifam->ifam_version != RTM_VERSION) {
			continue;
		}
		if (ifam->ifam_type != RTM_NEWADDR)
			break;
		if (ifam->ifam_addrs & RTA_IFA) {
			int i;
			char *cp = (char *)(ifam + 1);

			for (i = 1; i < RTA_IFA; i <<= 1) {
				if (ifam->ifam_addrs & i)
					cp += SA_SIZE((struct sockaddr *)cp);
			}
			if (((struct sockaddr *)cp)->sa_family == AF_INET) {
				sin = (struct sockaddr_in *)cp;
				break;
			}
		}
	}
	if (sin == NULL)
		errx(1, "%s: cannot get interface address", ifn);

	n->ip = sin->sin_addr;
	strncpy(n->if_name, ifn, IF_NAMESIZE);

	free(buf, M_IPFW);
}

/*
 * XXX - The following functions, macros and definitions come from natd.c:
 * it would be better to move them outside natd.c, in a file
 * (redirect_support.[ch]?) shared by ipfw and natd, but for now i can live
 * with it.
 */

/*
 * Definition of a port range, and macros to deal with values.
 * FORMAT:  HI 16-bits == first port in range, 0 == all ports.
 *          LO 16-bits == number of ports in range
 * NOTES:   - Port values are not stored in network byte order.
 */

#define port_range u_long

#define GETLOPORT(x)     ((x) >> 0x10)
#define GETNUMPORTS(x)   ((x) & 0x0000ffff)
#define GETHIPORT(x)     (GETLOPORT((x)) + GETNUMPORTS((x)))

/* Set y to be the low-port value in port_range variable x. */
#define SETLOPORT(x,y)   ((x) = ((x) & 0x0000ffff) | ((y) << 0x10))

/* Set y to be the number of ports in port_range variable x. */
#define SETNUMPORTS(x,y) ((x) = ((x) & 0xffff0000) | (y))

static void
StrToAddr (const char* str, struct in_addr* addr)
{
	struct hostent* hp;

	if (inet_aton (str, addr))
		return;

	hp = gethostbyname (str);
	if (!hp)
		errx (1, "unknown host %s", str);

	memcpy (addr, hp->h_addr, sizeof (struct in_addr));
}

static int
StrToPortRange (const char* str, const char* proto, port_range *portRange)
{
	char*           sep;
	struct servent*	sp;
	char*		end;
	u_short         loPort;
	u_short         hiPort;

	/* First see if this is a service, return corresponding port if so. */
	sp = getservbyname (str,proto);
	if (sp) {
	        SETLOPORT(*portRange, ntohs(sp->s_port));
		SETNUMPORTS(*portRange, 1);
		return 0;
	}

	/* Not a service, see if it's a single port or port range. */
	sep = strchr (str, '-');
	if (sep == NULL) {
	        SETLOPORT(*portRange, strtol(str, &end, 10));
		if (end != str) {
		        /* Single port. */
		        SETNUMPORTS(*portRange, 1);
			return 0;
		}

		/* Error in port range field. */
		errx (EX_DATAERR, "%s/%s: unknown service", str, proto);
	}

	/* Port range, get the values and sanity check. */
	sscanf (str, "%hu-%hu", &loPort, &hiPort);
	SETLOPORT(*portRange, loPort);
	SETNUMPORTS(*portRange, 0);	/* Error by default */
	if (loPort <= hiPort)
	        SETNUMPORTS(*portRange, hiPort - loPort + 1);

	if (GETNUMPORTS(*portRange) == 0)
	        errx (EX_DATAERR, "invalid port range %s", str);

	return 0;
}

static int
StrToProto (const char* str)
{
	if (!strcmp (str, "tcp"))
		return IPPROTO_TCP;

	if (!strcmp (str, "udp"))
		return IPPROTO_UDP;

	if (!strcmp (str, "sctp"))
		return IPPROTO_SCTP;
	errx (EX_DATAERR, "unknown protocol %s. Expected sctp, tcp or udp", str);
}

static int
StrToAddrAndPortRange (const char* str, struct in_addr* addr, char* proto,
		       port_range *portRange)
{
	char*	ptr;

	ptr = strchr (str, ':');
	if (!ptr)
		errx (EX_DATAERR, "%s is missing port number", str);

	*ptr = '\0';
	++ptr;

	StrToAddr (str, addr);
	return StrToPortRange (ptr, proto, portRange);
}

/* End of stuff taken from natd.c. */

#define INC_ARGCV() do {        \
	(*_av)++;               \
	(*_ac)--;               \
	av = *_av;              \
	ac = *_ac;              \
} while(0)

/*
 * The next 3 functions add support for the addr, port and proto redirect and
 * their logic is loosely based on SetupAddressRedirect(), SetupPortRedirect()
 * and SetupProtoRedirect() from natd.c.
 *
 * Every setup_* function fills at least one redirect entry
 * (struct cfg_redir) and zero or more server pool entry (struct cfg_spool)
 * in buf.
 *
 * The format of data in buf is:
 *
 *
 *     cfg_nat    cfg_redir    cfg_spool    ......  cfg_spool
 *
 *    -------------------------------------        ------------
 *   |          | .....X ... |          |         |           |  .....
 *    ------------------------------------- ...... ------------
 *                     ^
 *                spool_cnt       n=0       ......   n=(X-1)
 *
 * len points to the amount of available space in buf
 * space counts the memory consumed by every function
 *
 * XXX - Every function get all the argv params so it
 * has to check, in optional parameters, that the next
 * args is a valid option for the redir entry and not
 * another token. Only redir_port and redir_proto are
 * affected by this.
 */

static int
setup_redir_addr(char *spool_buf, unsigned int len,
		 int *_ac, char ***_av)
{
	char **av, *sep; /* Token separator. */
	/* Temporary buffer used to hold server pool ip's. */
	char tmp_spool_buf[NAT_BUF_LEN];
	int ac, space, lsnat;
	struct cfg_redir *r;
	struct cfg_spool *tmp;

	av = *_av;
	ac = *_ac;
	space = 0;
	lsnat = 0;
	if (len >= SOF_REDIR) {
		r = (struct cfg_redir *)spool_buf;
		/* Skip cfg_redir at beginning of buf. */
		spool_buf = &spool_buf[SOF_REDIR];
		space = SOF_REDIR;
		len -= SOF_REDIR;
	} else
		goto nospace;
	r->mode = REDIR_ADDR;
	/* Extract local address. */
	if (ac == 0)
		errx(EX_DATAERR, "redirect_addr: missing local address");
	sep = strchr(*av, ',');
	if (sep) {		/* LSNAT redirection syntax. */
		r->laddr.s_addr = INADDR_NONE;
		/* Preserve av, copy spool servers to tmp_spool_buf. */
		strncpy(tmp_spool_buf, *av, strlen(*av)+1);
		lsnat = 1;
	} else
		StrToAddr(*av, &r->laddr);
	INC_ARGCV();

	/* Extract public address. */
	if (ac == 0)
		errx(EX_DATAERR, "redirect_addr: missing public address");
	StrToAddr(*av, &r->paddr);
	INC_ARGCV();

	/* Setup LSNAT server pool. */
	if (sep) {
		sep = strtok(tmp_spool_buf, ",");
		while (sep != NULL) {
			tmp = (struct cfg_spool *)spool_buf;
			if (len < SOF_SPOOL)
				goto nospace;
			len -= SOF_SPOOL;
			space += SOF_SPOOL;
			StrToAddr(sep, &tmp->addr);
			tmp->port = ~0;
			r->spool_cnt++;
			/* Point to the next possible cfg_spool. */
			spool_buf = &spool_buf[SOF_SPOOL];
			sep = strtok(NULL, ",");
		}
	}
	return(space);
nospace:
	errx(EX_DATAERR, "redirect_addr: buf is too small\n");
}

static int
setup_redir_port(char *spool_buf, unsigned int len,
		 int *_ac, char ***_av)
{
	char **av, *sep, *protoName;
	char tmp_spool_buf[NAT_BUF_LEN];
	int ac, space, lsnat;
	struct cfg_redir *r;
	struct cfg_spool *tmp;
	u_short numLocalPorts;
	port_range portRange;

	av = *_av;
	ac = *_ac;
	space = 0;
	lsnat = 0;
	numLocalPorts = 0;

	if (len >= SOF_REDIR) {
		r = (struct cfg_redir *)spool_buf;
		/* Skip cfg_redir at beginning of buf. */
		spool_buf = &spool_buf[SOF_REDIR];
		space = SOF_REDIR;
		len -= SOF_REDIR;
	} else
		goto nospace;
	r->mode = REDIR_PORT;
	/*
	 * Extract protocol.
	 */
	if (ac == 0)
		errx (EX_DATAERR, "redirect_port: missing protocol");
	r->proto = StrToProto(*av);
	protoName = *av;
	INC_ARGCV();

	/*
	 * Extract local address.
	 */
	if (ac == 0)
		errx (EX_DATAERR, "redirect_port: missing local address");

	sep = strchr(*av, ',');
	/* LSNAT redirection syntax. */
	if (sep) {
		r->laddr.s_addr = INADDR_NONE;
		r->lport = ~0;
		numLocalPorts = 1;
		/* Preserve av, copy spool servers to tmp_spool_buf. */
		strncpy(tmp_spool_buf, *av, strlen(*av)+1);
		lsnat = 1;
	} else {
		/*
		 * The sctp nat does not allow the port numbers to be mapped to
		 * new port numbers. Therefore, no ports are to be specified
		 * in the target port field.
		 */
		if (r->proto == IPPROTO_SCTP) {
			if (strchr (*av, ':'))
				errx(EX_DATAERR, "redirect_port:"
				    "port numbers do not change in sctp, so do not "
				    "specify them as part of the target");
			else
				StrToAddr(*av, &r->laddr);
		} else {
			if (StrToAddrAndPortRange (*av, &r->laddr, protoName,
				&portRange) != 0)
				errx(EX_DATAERR, "redirect_port:"
				    "invalid local port range");

			r->lport = GETLOPORT(portRange);
			numLocalPorts = GETNUMPORTS(portRange);
		}
	}
	INC_ARGCV();

	/*
	 * Extract public port and optionally address.
	 */
	if (ac == 0)
		errx (EX_DATAERR, "redirect_port: missing public port");

	sep = strchr (*av, ':');
	if (sep) {
	        if (StrToAddrAndPortRange (*av, &r->paddr, protoName,
		    &portRange) != 0)
		        errx(EX_DATAERR, "redirect_port:"
			    "invalid public port range");
	} else {
		r->paddr.s_addr = INADDR_ANY;
		if (StrToPortRange (*av, protoName, &portRange) != 0)
		        errx(EX_DATAERR, "redirect_port:"
			    "invalid public port range");
	}

	r->pport = GETLOPORT(portRange);
	if (r->proto == IPPROTO_SCTP) { /* so the logic below still works */
		numLocalPorts = GETNUMPORTS(portRange);
		r->lport = r->pport;
	}
	r->pport_cnt = GETNUMPORTS(portRange);
	INC_ARGCV();

	/*
	 * Extract remote address and optionally port.
	 */
	/*
	 * NB: isalpha(**av) => we've to check that next parameter is really an
	 * option for this redirect entry, else stop here processing arg[cv].
	 */
	if (ac != 0 && !isalpha(**av)) {
		sep = strchr (*av, ':');
		if (sep) {
		        if (StrToAddrAndPortRange (*av, &r->raddr, protoName,
			    &portRange) != 0)
				errx(EX_DATAERR, "redirect_port:"
				    "invalid remote port range");
		} else {
		        SETLOPORT(portRange, 0);
			SETNUMPORTS(portRange, 1);
			StrToAddr (*av, &r->raddr);
		}
		INC_ARGCV();
	} else {
		SETLOPORT(portRange, 0);
		SETNUMPORTS(portRange, 1);
		r->raddr.s_addr = INADDR_ANY;
	}
	r->rport = GETLOPORT(portRange);
	r->rport_cnt = GETNUMPORTS(portRange);

	/*
	 * Make sure port ranges match up, then add the redirect ports.
	 */
	if (numLocalPorts != r->pport_cnt)
	        errx(EX_DATAERR, "redirect_port:"
		    "port ranges must be equal in size");

	/* Remote port range is allowed to be '0' which means all ports. */
	if (r->rport_cnt != numLocalPorts &&
	    (r->rport_cnt != 1 || r->rport != 0))
	        errx(EX_DATAERR, "redirect_port: remote port must"
		    "be 0 or equal to local port range in size");

	/*
	 * Setup LSNAT server pool.
	 */
	if (lsnat) {
		sep = strtok(tmp_spool_buf, ",");
		while (sep != NULL) {
			tmp = (struct cfg_spool *)spool_buf;
			if (len < SOF_SPOOL)
				goto nospace;
			len -= SOF_SPOOL;
			space += SOF_SPOOL;
			/*
			 * The sctp nat does not allow the port numbers to be mapped to new port numbers
			 * Therefore, no ports are to be specified in the target port field
			 */
			if (r->proto == IPPROTO_SCTP) {
				if (strchr (sep, ':')) {
					errx(EX_DATAERR, "redirect_port:"
					    "port numbers do not change in "
					    "sctp, so do not specify them as "
					    "part of the target");
				} else {
					StrToAddr(sep, &tmp->addr);
					tmp->port = r->pport;
				}
			} else {
				if (StrToAddrAndPortRange(sep, &tmp->addr,
					protoName, &portRange) != 0)
					errx(EX_DATAERR, "redirect_port:"
					    "invalid local port range");
				if (GETNUMPORTS(portRange) != 1)
					errx(EX_DATAERR, "redirect_port: "
					    "local port must be single in "
					    "this context");
				tmp->port = GETLOPORT(portRange);
			}
			r->spool_cnt++;
			/* Point to the next possible cfg_spool. */
			spool_buf = &spool_buf[SOF_SPOOL];
			sep = strtok(NULL, ",");
		}
	}
	return (space);
nospace:
	errx(EX_DATAERR, "redirect_port: buf is too small\n");
}

static int
setup_redir_proto(char *spool_buf, unsigned int len,
		 int *_ac, char ***_av)
{
	char **av;
	int ac, space;
	struct protoent *protoent;
	struct cfg_redir *r;

	av = *_av;
	ac = *_ac;
	if (len >= SOF_REDIR) {
		r = (struct cfg_redir *)spool_buf;
		/* Skip cfg_redir at beginning of buf. */
		spool_buf = &spool_buf[SOF_REDIR];
		space = SOF_REDIR;
		len -= SOF_REDIR;
	} else
		goto nospace;
	r->mode = REDIR_PROTO;
	/*
	 * Extract protocol.
	 */
	if (ac == 0)
		errx(EX_DATAERR, "redirect_proto: missing protocol");

	protoent = getprotobyname(*av);
	if (protoent == NULL)
		errx(EX_DATAERR, "redirect_proto: unknown protocol %s", *av);
	else
		r->proto = protoent->p_proto;

	INC_ARGCV();

	/*
	 * Extract local address.
	 */
	if (ac == 0)
		errx(EX_DATAERR, "redirect_proto: missing local address");
	else
		StrToAddr(*av, &r->laddr);

	INC_ARGCV();

	/*
	 * Extract optional public address.
	 */
	if (ac == 0) {
		r->paddr.s_addr = INADDR_ANY;
		r->raddr.s_addr = INADDR_ANY;
	} else {
		/* see above in setup_redir_port() */
		if (!isalpha(**av)) {
			StrToAddr(*av, &r->paddr);
			INC_ARGCV();

			/*
			 * Extract optional remote address.
			 */
			/* see above in setup_redir_port() */
			if (ac!=0 && !isalpha(**av)) {
				StrToAddr(*av, &r->raddr);
				INC_ARGCV();
			}
		}
	}
	return (space);
nospace:
	errx(EX_DATAERR, "redirect_proto: buf is too small\n");
}

static void
print_nat_config(unsigned char *buf)
{
	struct cfg_nat *n;
	int i, cnt, flag, off;
	struct cfg_redir *t;
	struct cfg_spool *s;
	struct protoent *p;

	n = (struct cfg_nat *)buf;
	flag = 1;
	off  = sizeof(*n);
	printf("ipfw nat %u config", n->id);
	if (strlen(n->if_name) != 0)
		printf(" if %s", n->if_name);
	else if (n->ip.s_addr != 0)
		printf(" ip %s", inet_ntoa(n->ip));
	while (n->mode != 0) {
		if (n->mode & PKT_ALIAS_LOG) {
			printf(" log");
			n->mode &= ~PKT_ALIAS_LOG;
		} else if (n->mode & PKT_ALIAS_DENY_INCOMING) {
			printf(" deny_in");
			n->mode &= ~PKT_ALIAS_DENY_INCOMING;
		} else if (n->mode & PKT_ALIAS_SAME_PORTS) {
			printf(" same_ports");
			n->mode &= ~PKT_ALIAS_SAME_PORTS;
		} else if (n->mode & PKT_ALIAS_UNREGISTERED_ONLY) {
			printf(" unreg_only");
			n->mode &= ~PKT_ALIAS_UNREGISTERED_ONLY;
		} else if (n->mode & PKT_ALIAS_RESET_ON_ADDR_CHANGE) {
			printf(" reset");
			n->mode &= ~PKT_ALIAS_RESET_ON_ADDR_CHANGE;
		} else if (n->mode & PKT_ALIAS_REVERSE) {
			printf(" reverse");
			n->mode &= ~PKT_ALIAS_REVERSE;
		} else if (n->mode & PKT_ALIAS_PROXY_ONLY) {
			printf(" proxy_only");
			n->mode &= ~PKT_ALIAS_PROXY_ONLY;
		}
	}
	/* Print all the redirect's data configuration. */
	for (cnt = 0; cnt < n->redir_cnt; cnt++) {
		t = (struct cfg_redir *)&buf[off];
		off += SOF_REDIR;
		switch (t->mode) {
		case REDIR_ADDR:
			printf(" redirect_addr");
			if (t->spool_cnt == 0)
				printf(" %s", inet_ntoa(t->laddr));
			else
				for (i = 0; i < t->spool_cnt; i++) {
					s = (struct cfg_spool *)&buf[off];
					if (i)
						printf(",");
					else
						printf(" ");
					printf("%s", inet_ntoa(s->addr));
					off += SOF_SPOOL;
				}
			printf(" %s", inet_ntoa(t->paddr));
			break;
		case REDIR_PORT:
			p = getprotobynumber(t->proto);
			printf(" redirect_port %s ", p->p_name);
			if (!t->spool_cnt) {
				printf("%s:%u", inet_ntoa(t->laddr), t->lport);
				if (t->pport_cnt > 1)
					printf("-%u", t->lport +
					    t->pport_cnt - 1);
			} else
				for (i=0; i < t->spool_cnt; i++) {
					s = (struct cfg_spool *)&buf[off];
					if (i)
						printf(",");
					printf("%s:%u", inet_ntoa(s->addr),
					    s->port);
					off += SOF_SPOOL;
				}

			printf(" ");
			if (t->paddr.s_addr)
				printf("%s:", inet_ntoa(t->paddr));
			printf("%u", t->pport);
			if (!t->spool_cnt && t->pport_cnt > 1)
				printf("-%u", t->pport + t->pport_cnt - 1);

			if (t->raddr.s_addr) {
				printf(" %s", inet_ntoa(t->raddr));
				if (t->rport) {
					printf(":%u", t->rport);
					if (!t->spool_cnt && t->rport_cnt > 1)
						printf("-%u", t->rport +
						    t->rport_cnt - 1);
				}
			}
			break;
		case REDIR_PROTO:
			p = getprotobynumber(t->proto);
			printf(" redirect_proto %s %s", p->p_name,
			    inet_ntoa(t->laddr));
			if (t->paddr.s_addr != 0) {
				printf(" %s", inet_ntoa(t->paddr));
				if (t->raddr.s_addr)
					printf(" %s", inet_ntoa(t->raddr));
			}
			break;
		default:
			errx(EX_DATAERR, "unknown redir mode");
			break;
		}
	}
	printf("\n");
}

void
ipfw_config_nat(int ac, char **av)
{
	struct cfg_nat *n;              /* Nat instance configuration. */
	int i, len, off, tok;
	char *id, buf[NAT_BUF_LEN]; 	/* Buffer for serialized data. */
	struct ip_fw_chain *chain = &layer3_chain;

	len = NAT_BUF_LEN;
	/* Offset in buf: save space for n at the beginning. */
	off = sizeof(*n);
	memset(buf, 0, sizeof(buf));
	n = (struct cfg_nat *)buf;

	av++; ac--;
	/* Nat id. */
	if (ac && isdigit(**av)) {
		id = *av;
		i = atoi(*av);
		ac--; av++;
		n->id = i;
	} else
		errx(EX_DATAERR, "missing nat id");
	if (ac == 0)
		errx(EX_DATAERR, "missing option");

	while (ac > 0) {
		tok = match_token(nat_params, *av);
		ac--; av++;
		switch (tok) {
		case TOK_IP:
			if (ac == 0)
				errx(EX_DATAERR, "missing option");
			if (!inet_aton(av[0], &(n->ip)))
				errx(EX_DATAERR, "bad ip address ``%s''",
				    av[0]);
			ac--; av++;
			break;
		case TOK_IF:
			if (ac == 0)
				errx(EX_DATAERR, "missing option");
			set_addr_dynamic(av[0], n);
			ac--; av++;
			break;
		case TOK_ALOG:
			n->mode |= PKT_ALIAS_LOG;
			break;
		case TOK_DENY_INC:
			n->mode |= PKT_ALIAS_DENY_INCOMING;
			break;
		case TOK_SAME_PORTS:
			n->mode |= PKT_ALIAS_SAME_PORTS;
			break;
		case TOK_UNREG_ONLY:
			n->mode |= PKT_ALIAS_UNREGISTERED_ONLY;
			break;
		case TOK_RESET_ADDR:
			n->mode |= PKT_ALIAS_RESET_ON_ADDR_CHANGE;
			break;
		case TOK_ALIAS_REV:
			n->mode |= PKT_ALIAS_REVERSE;
			break;
		case TOK_PROXY_ONLY:
			n->mode |= PKT_ALIAS_PROXY_ONLY;
			break;
			/*
			 * All the setup_redir_* functions work directly in the final
			 * buffer, see above for details.
			 */
		case TOK_REDIR_ADDR:
		case TOK_REDIR_PORT:
		case TOK_REDIR_PROTO:
			switch (tok) {
			case TOK_REDIR_ADDR:
				i = setup_redir_addr(&buf[off], len, &ac, &av);
				break;
			case TOK_REDIR_PORT:
				i = setup_redir_port(&buf[off], len, &ac, &av);
				break;
			case TOK_REDIR_PROTO:
				i = setup_redir_proto(&buf[off], len, &ac, &av);
				break;
			}
			n->redir_cnt++;
			off += i;
			len -= i;
			break;
		default:
			errx(EX_DATAERR, "unrecognised option ``%s''", av[-1]);
		}
	}

	char* nat_rule = (char*) malloc(NAT_BUF_LEN,  M_IPFW, M_WAITOK | M_ZERO);
	memcpy(nat_rule, n, NAT_BUF_LEN);
	struct cfg_nat * rule = (struct cfg_nat* )nat_rule;
	rule->lib = LibAliasInit(NULL);
	LIST_INIT(&rule->redir_chain);

	/*
	 * XXX - what if this rule doesn't nat any ip and just
	 * redirect?
	 * do we set aliasaddress to 0.0.0.0?
	 */

	LibAliasSetMode(rule->lib, rule->mode, rule->mode);
	LibAliasSetAddress(rule->lib, rule->ip);
	
	add_redir_spool_cfg(&buf[(sizeof(struct cfg_nat))], rule);
	if(chain->nat.lh_first != NULL)
	{
		struct cfg_nat *res = chain->nat.lh_first;
		while(res->_next.le_next) res = res->_next.le_next;
		LIST_INSERT_AFTER(res, rule, _next);
	}
	else
	{
	    ipfw_nat_cfg((struct cfg_nat *)nat_rule);
	    free(nat_rule, M_IPFW);
	}
}


void
ipfw_show_nat(int ac, char **av)
{
	struct cfg_nat *n;
	struct cfg_redir *e;
	int cmd, i, nbytes, do_cfg, do_rule, frule, lrule, nalloc, size;
	int nat_cnt, redir_cnt, r;
	uint8_t *data, *p;
	char *endptr;

	do_rule = 0;
	nalloc = 1024;
	size = 0;
	data = NULL;
	frule = 0;
	lrule = IPFW_DEFAULT_RULE; /* max ipfw rule number */
	ac--; av++;

	if (co.test_only)
		return;

	/* Parse parameters. */
	for (cmd = IP_FW_NAT_GET_LOG, do_cfg = 0; ac != 0; ac--, av++) {
		if (!strncmp(av[0], "config", strlen(av[0]))) {
			cmd = IP_FW_NAT_GET_CONFIG, do_cfg = 1;
			continue;
		}
		/* Convert command line rule #. */
		frule = lrule = strtoul(av[0], &endptr, 10);
		if (*endptr == '-')
			lrule = strtoul(endptr+1, &endptr, 10);
		if (lrule == 0)
			err(EX_USAGE, "invalid rule number: %s", av[0]);
		do_rule = 1;
	}

	nbytes = nalloc;
	while (nbytes >= nalloc) {
		nalloc = nalloc * 2;
		nbytes = nalloc;
		data = safe_realloc(data, nbytes);
		/*if (do_cmd(cmd, data, (uintptr_t)&nbytes) < 0)
			err(EX_OSERR, "getsockopt(IP_FW_GET_%s)",
			    (cmd == IP_FW_NAT_GET_LOG) ? "LOG" : "CONFIG");*/
	}
	if (nbytes == 0)
		exit(0);
	if (do_cfg) {
		nat_cnt = *((int *)data);
		for (i = sizeof(nat_cnt); nat_cnt; nat_cnt--) {
			n = (struct cfg_nat *)&data[i];
			if (frule <= n->id && lrule >= n->id)
				print_nat_config(&data[i]);
			i += sizeof(struct cfg_nat);
			for (redir_cnt = 0; redir_cnt < n->redir_cnt; redir_cnt++) {
				e = (struct cfg_redir *)&data[i];
				i += sizeof(struct cfg_redir) + e->spool_cnt *
				    sizeof(struct cfg_spool);
			}
		}
	} else {
		for (i = 0; 1; i += LIBALIAS_BUF_SIZE + sizeof(int)) {
			p = &data[i];
			if (p == data + nbytes)
				break;
			bcopy(p, &r, sizeof(int));
			if (do_rule) {
				if (!(frule <= r && lrule >= r))
					continue;
			}
			printf("nat %u: %s\n", r, p+sizeof(int));
		}
	}
}
