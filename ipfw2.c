#include <cyg/posix/mutex.h>
#include <cyg/kernel/kapi.h>

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/netisr.h>
#include <net/intrq.h>
#include <netdb.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socketvar.h>
#include <netinet/ip_fw.h>
#include <net/ethernet.h>

#include "ip_fw_private.h"
#include "ipfw2.h"

extern struct ip_fw_chain layer3_chain;

struct cmdline_opts co;	/* global options */

#define GET_UINT_ARG(arg, min, max, tok, s_x) do {			\
	if (!av[0])							\
		errx(EX_USAGE, "%s: missing argument", match_value(s_x, tok)); \
	if (_substrcmp(*av, "tablearg") == 0) {				\
		arg = IP_FW_TABLEARG;					\
		break;							\
	}								\
									\
	{								\
	long _xval;							\
	char *end;							\
									\
	_xval = strtol(*av, &end, 10);					\
									\
	if (!isdigit(**av) || *end != '\0' || (_xval == 0 && errno == EINVAL)) \
		errx(EX_DATAERR, "%s: invalid argument: %s",		\
		    match_value(s_x, tok), *av);			\
									\
	if (errno == ERANGE || _xval < min || _xval > max)		\
		errx(EX_DATAERR, "%s: argument is out of range (%u..%u): %s", \
		    match_value(s_x, tok), min, max, *av);		\
									\
	if (_xval == IP_FW_TABLEARG)					\
		errx(EX_DATAERR, "%s: illegal argument value: %s",	\
		    match_value(s_x, tok), *av);			\
	arg = _xval;							\
	}								\
} while (0)

static struct _s_x f_tcpflags[] = {
	{ "syn", TH_SYN },
	{ "fin", TH_FIN },
	{ "ack", TH_ACK },
	{ "psh", TH_PUSH },
	{ "rst", TH_RST },
	{ "urg", TH_URG },
	{ "tcp flag", 0 },
	{ NULL,	0 }
};

static struct _s_x f_tcpopts[] = {
	{ "mss",	IP_FW_TCPOPT_MSS },
	{ "maxseg",	IP_FW_TCPOPT_MSS },
	{ "window",	IP_FW_TCPOPT_WINDOW },
	{ "sack",	IP_FW_TCPOPT_SACK },
	{ "ts",		IP_FW_TCPOPT_TS },
	{ "timestamp",	IP_FW_TCPOPT_TS },
	{ "cc",		IP_FW_TCPOPT_CC },
	{ "tcp option",	0 },
	{ NULL,	0 }
};

/*
 * IP options span the range 0 to 255 so we need to remap them
 * (though in fact only the low 5 bits are significant).
 */
static struct _s_x f_ipopts[] = {
	{ "ssrr",	IP_FW_IPOPT_SSRR},
	{ "lsrr",	IP_FW_IPOPT_LSRR},
	{ "rr",		IP_FW_IPOPT_RR},
	{ "ts",		IP_FW_IPOPT_TS},
	{ "ip option",	0 },
	{ NULL,	0 }
};

static struct _s_x f_iptos[] = {
	{ "lowdelay",	IPTOS_LOWDELAY},
	{ "throughput",	IPTOS_THROUGHPUT},
	{ "reliability", IPTOS_RELIABILITY},
	{ "mincost",	IPTOS_MINCOST},
	{ "congestion",	IPTOS_ECN_CE},
	{ "ecntransport", IPTOS_ECN_ECT0},
	{ "ip tos option", 0},
	{ NULL,	0 }
};

static struct _s_x limit_masks[] = {
	{"all",		DYN_SRC_ADDR|DYN_SRC_PORT|DYN_DST_ADDR|DYN_DST_PORT},
	{"src-addr",	DYN_SRC_ADDR},
	{"src-port",	DYN_SRC_PORT},
	{"dst-addr",	DYN_DST_ADDR},
	{"dst-port",	DYN_DST_PORT},
	{NULL,		0}
};

/*
 * we use IPPROTO_ETHERTYPE as a fake protocol id to call the print routines
 * This is only used in this code.
 */
#define IPPROTO_ETHERTYPE	0x1000
static struct _s_x ether_types[] = {
    /*
     * Note, we cannot use "-:&/" in the names because they are field
     * separators in the type specifications. Also, we use s = NULL as
     * end-delimiter, because a type of 0 can be legal.
     */
	{ "ip",		0x0800 },
	{ "ipv4",	0x0800 },
	{ "ipv6",	0x86dd },
	{ "arp",	0x0806 },
	{ "rarp",	0x8035 },
	{ "vlan",	0x8100 },
	{ "loop",	0x9000 },
	{ "trail",	0x1000 },
	{ "at",		0x809b },
	{ "atalk",	0x809b },
	{ "aarp",	0x80f3 },
	{ "pppoe_disc",	0x8863 },
	{ "pppoe_sess",	0x8864 },
	{ "ipx_8022",	0x00E0 },
	{ "ipx_8023",	0x0000 },
	{ "ipx_ii",	0x8137 },
	{ "ipx_snap",	0x8137 },
	{ "ipx",	0x8137 },
	{ "ns",		0x0600 },
	{ NULL,		0 }
};


static struct _s_x rule_actions[] = {
	{ "accept",		TOK_ACCEPT },
	{ "pass",		TOK_ACCEPT },
	{ "allow",		TOK_ACCEPT },
	{ "permit",		TOK_ACCEPT },
	{ "count",		TOK_COUNT },
	{ "pipe",		TOK_PIPE },
	{ "queue",		TOK_QUEUE },
	{ "divert",		TOK_DIVERT },
	{ "tee",		TOK_TEE },
	{ "netgraph",		TOK_NETGRAPH },
	{ "ngtee",		TOK_NGTEE },
	{ "fwd",		TOK_FORWARD },
	{ "forward",		TOK_FORWARD },
	{ "skipto",		TOK_SKIPTO },
	{ "deny",		TOK_DENY },
	{ "drop",		TOK_DENY },
	{ "reject",		TOK_REJECT },
	{ "reset6",		TOK_RESET6 },
	{ "reset",		TOK_RESET },
	{ "unreach6",		TOK_UNREACH6 },
	{ "unreach",		TOK_UNREACH },
	{ "check-state",	TOK_CHECKSTATE },
	{ "//",			TOK_COMMENT },
	{ "nat",                TOK_NAT },
	{ "reass",		TOK_REASS },
	{ "setfib",		TOK_SETFIB },
	{ NULL, 0 }	/* terminator */
};

static struct _s_x rule_action_params[] = {
	{ "altq",		TOK_ALTQ },
	{ "log",		TOK_LOG },
	{ "tag",		TOK_TAG },
	{ "untag",		TOK_UNTAG },
	{ NULL, 0 }	/* terminator */
};

/*
 * The 'lookup' instruction accepts one of the following arguments.
 * -1 is a terminator for the list.
 * Arguments are passed as v[1] in O_DST_LOOKUP options.
 */
static int lookup_key[] = {
	TOK_DSTIP, TOK_SRCIP, TOK_DSTPORT, TOK_SRCPORT,
	TOK_UID, TOK_JAIL, TOK_DSCP, -1 };

static struct _s_x rule_options[] = {
	{ "tagged",		TOK_TAGGED },
	{ "uid",		TOK_UID },
	{ "gid",		TOK_GID },
	{ "jail",		TOK_JAIL },
	{ "in",			TOK_IN },
	{ "limit",		TOK_LIMIT },
	{ "keep-state",		TOK_KEEPSTATE },
	{ "bridged",		TOK_LAYER2 },
	{ "layer2",		TOK_LAYER2 },
	{ "out",		TOK_OUT },
	{ "diverted",		TOK_DIVERTED },
	{ "diverted-loopback",	TOK_DIVERTEDLOOPBACK },
	{ "diverted-output",	TOK_DIVERTEDOUTPUT },
	{ "xmit",		TOK_XMIT },
	{ "recv",		TOK_RECV },
	{ "via",		TOK_VIA },
	{ "fragment",		TOK_FRAG },
	{ "frag",		TOK_FRAG },
	{ "fib",		TOK_FIB },
	{ "ipoptions",		TOK_IPOPTS },
	{ "ipopts",		TOK_IPOPTS },
	{ "iplen",		TOK_IPLEN },
	{ "ipid",		TOK_IPID },
	{ "ipprecedence",	TOK_IPPRECEDENCE },
	{ "dscp",		TOK_DSCP },
	{ "iptos",		TOK_IPTOS },
	{ "ipttl",		TOK_IPTTL },
	{ "ipversion",		TOK_IPVER },
	{ "ipver",		TOK_IPVER },
	{ "estab",		TOK_ESTAB },
	{ "established",	TOK_ESTAB },
	{ "setup",		TOK_SETUP },
	{ "tcpdatalen",		TOK_TCPDATALEN },
	{ "tcpflags",		TOK_TCPFLAGS },
	{ "tcpflgs",		TOK_TCPFLAGS },
	{ "tcpoptions",		TOK_TCPOPTS },
	{ "tcpopts",		TOK_TCPOPTS },
	{ "tcpseq",		TOK_TCPSEQ },
	{ "tcpack",		TOK_TCPACK },
	{ "tcpwin",		TOK_TCPWIN },
	{ "icmptype",		TOK_ICMPTYPES },
	{ "icmptypes",		TOK_ICMPTYPES },
	{ "dst-ip",		TOK_DSTIP },
	{ "src-ip",		TOK_SRCIP },
	{ "dst-port",		TOK_DSTPORT },
	{ "src-port",		TOK_SRCPORT },
	{ "proto",		TOK_PROTO },
	{ "MAC",		TOK_MAC },
	{ "mac",		TOK_MAC },
	{ "mac-type",		TOK_MACTYPE },
	{ "verrevpath",		TOK_VERREVPATH },
	{ "versrcreach",	TOK_VERSRCREACH },
	{ "antispoof",		TOK_ANTISPOOF },
	{ "ipsec",		TOK_IPSEC },
	{ "icmp6type",		TOK_ICMP6TYPES },
	{ "icmp6types",		TOK_ICMP6TYPES },
	{ "ext6hdr",		TOK_EXT6HDR},
	{ "flow-id",		TOK_FLOWID},
	{ "ipv6",		TOK_IPV6},
	{ "ip6",		TOK_IPV6},
	{ "ipv4",		TOK_IPV4},
	{ "ip4",		TOK_IPV4},
	{ "dst-ipv6",		TOK_DSTIP6},
	{ "dst-ip6",		TOK_DSTIP6},
	{ "src-ipv6",		TOK_SRCIP6},
	{ "src-ip6",		TOK_SRCIP6},
	{ "lookup",		TOK_LOOKUP},
	{ "//",			TOK_COMMENT },

	{ "not",		TOK_NOT },		/* pseudo option */
	{ "!", /* escape ? */	TOK_NOT },		/* pseudo option */
	{ "or",			TOK_OR },		/* pseudo option */
	{ "|", /* escape */	TOK_OR },		/* pseudo option */
	{ "{",			TOK_STARTBRACE },	/* pseudo option */
	{ "(",			TOK_STARTBRACE },	/* pseudo option */
	{ "}",			TOK_ENDBRACE },		/* pseudo option */
	{ ")",			TOK_ENDBRACE },		/* pseudo option */
	{ NULL, 0 }	/* terminator */
};

static struct _s_x icmpcodes[] = {
      { "net",			ICMP_UNREACH_NET },
      { "host",			ICMP_UNREACH_HOST },
      { "protocol",		ICMP_UNREACH_PROTOCOL },
      { "port",			ICMP_UNREACH_PORT },
      { "needfrag",		ICMP_UNREACH_NEEDFRAG },
      { "srcfail",		ICMP_UNREACH_SRCFAIL },
      { "net-unknown",		ICMP_UNREACH_NET_UNKNOWN },
      { "host-unknown",		ICMP_UNREACH_HOST_UNKNOWN },
      { "isolated",		ICMP_UNREACH_ISOLATED },
      { "net-prohib",		ICMP_UNREACH_NET_PROHIB },
      { "host-prohib",		ICMP_UNREACH_HOST_PROHIB },
      { "tosnet",		ICMP_UNREACH_TOSNET },
      { "toshost",		ICMP_UNREACH_TOSHOST },
      { "filter-prohib",	ICMP_UNREACH_FILTER_PROHIB },
      { "host-precedence",	ICMP_UNREACH_HOST_PRECEDENCE },
      { "precedence-cutoff",	ICMP_UNREACH_PRECEDENCE_CUTOFF },
      { NULL, 0 }
};
ipfw_nat_t *ipfw_nat_ptr = NULL;
struct cfg_nat *(*lookup_nat_ptr)(struct nat_list *, int);
ipfw_nat_cfg_t *ipfw_nat_cfg_ptr;
ipfw_nat_cfg_t *ipfw_nat_get_cfg_ptr;

void errx(int eval, const char * fmt, ...)
{
    
}
void *
safe_calloc(size_t number, size_t size)
{
	void *ret = calloc(number, size);
	return ret;
}


static void
fill_reject_code(u_short *codep, char *str)
{
	int val;
	char *s;

	val = strtoul(str, &s, 0);
	if (s == str || *s != '\0' || val >= 0x100)
		val = match_token(icmpcodes, str);
	if (val < 0)
		errx(EX_DATAERR, "unknown ICMP unreachable code ``%s''", str);
	*codep = val;
	return;
}


/*
 * Returns the number of bits set (from left) in a contiguous bitmask,
 * or -1 if the mask is not contiguous.
 * XXX this needs a proper fix.
 * This effectively works on masks in big-endian (network) format.
 * when compiled on little endian architectures.
 *
 * First bit is bit 7 of the first byte -- note, for MAC addresses,
 * the first bit on the wire is bit 0 of the first byte.
 * len is the max length in bits.
 */
int
contigmask(uint8_t *p, int len)
{
	int i, n;

	for (i=0; i<len ; i++)
		if ( (p[i/8] & (1 << (7 - (i%8)))) == 0) /* first bit unset */
			break;
	for (n=i+1; n < len; n++)
		if ( (p[n/8] & (1 << (7 - (n%8)))) != 0)
			return -1; /* mask not contiguous */
	return i;
}

static void
fill_icmptypes(ipfw_insn_u32 *cmd, char *av)
{
	uint8_t type;

	cmd->d[0] = 0;
	while (*av) {
		if (*av == ',')
			av++;

		type = strtoul(av, &av, 0);

		if (*av != ',' && *av != '\0')
			errx(EX_DATAERR, "invalid ICMP type");

		if (type > 31)
			errx(EX_DATAERR, "ICMP type out of range");

		cmd->d[0] |= 1 << type;
	}
	cmd->o.opcode = O_ICMPTYPE;
	cmd->o.len |= F_INSN_SIZE(ipfw_insn_u32);
}

static void
get_mac_addr_mask(const char *p, uint8_t *addr, uint8_t *mask)
{
	int i;
	size_t l;
	char *ap, *ptr, *optr;
	struct ether_addr *mac;
	const char *macset = "0123456789abcdefABCDEF:";

	if (strcmp(p, "any") == 0) {
		for (i = 0; i < ETHER_ADDR_LEN; i++)
			addr[i] = mask[i] = 0;
		return;
	}

	optr = ptr = strdup(p);
	if ((ap = strsep(&ptr, "&/")) != NULL && *ap != 0) {
		l = strlen(ap);
		if (strspn(ap, macset) != l || (mac = ether_aton(ap)) == NULL)
			errx(EX_DATAERR, "Incorrect MAC address");
		bcopy(mac, addr, ETHER_ADDR_LEN);
	} else
		errx(EX_DATAERR, "Incorrect MAC address");

	if (ptr != NULL) { /* we have mask? */
		if (p[ptr - optr - 1] == '/') { /* mask len */
			long ml = strtol(ptr, &ap, 10);
			if (*ap != 0 || ml > ETHER_ADDR_LEN * 8 || ml < 0)
				errx(EX_DATAERR, "Incorrect mask length");
			for (i = 0; ml > 0 && i < ETHER_ADDR_LEN; ml -= 8, i++)
				mask[i] = (ml >= 8) ? 0xff: (~0) << (8 - ml);
		} else { /* mask */
			l = strlen(ptr);
			if (strspn(ptr, macset) != l ||
			    (mac = ether_aton(ptr)) == NULL)
				errx(EX_DATAERR, "Incorrect mask");
			bcopy(mac, mask, ETHER_ADDR_LEN);
		}
	} else { /* default mask: ff:ff:ff:ff:ff:ff */
		for (i = 0; i < ETHER_ADDR_LEN; i++)
			mask[i] = 0xff;
	}
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		addr[i] &= mask[i];

	free(optr, M_IPFW);
}
/*
 * helper function, updates the pointer to cmd with the length
 * of the current command, and also cleans up the first word of
 * the new command in case it has been clobbered before.
 */
static ipfw_insn *
next_cmd(ipfw_insn *cmd)
{
	cmd += F_LEN(cmd);
	bzero(cmd, sizeof(*cmd));
	return cmd;
}
/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = *s++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* count does not include NUL */
}

/*
 * fill the interface structure. We do not check the name as we can
 * create interfaces dynamically, so checking them at insert time
 * makes relatively little sense.
 * Interface names containing '*', '?', or '[' are assumed to be shell
 * patterns which match interfaces.
 */
static void
fill_iface(ipfw_insn_if *cmd, char *arg)
{
	cmd->name[0] = '\0';
	cmd->o.len |= F_INSN_SIZE(ipfw_insn_if);

	/* Parse the interface or address */
	if (strcmp(arg, "any") == 0)
		cmd->o.len = 0;		/* effectively ignore this command */
	else if (!isdigit(*arg)) {
		strlcpy(cmd->name, arg, sizeof(cmd->name));
		cmd->p.glob = strpbrk(arg, "*?[") != NULL ? 1 : 0;
	} else if (!inet_aton(arg, &cmd->p.ip))
		errx(EX_DATAERR, "bad ip address ``%s''", arg);
}

/*
 * Takes arguments and copies them into a comment
 */
static void
fill_comment(ipfw_insn *cmd, char **av)
{
	int i, l;
	char *p = (char *)(cmd + 1);

	cmd->opcode = O_NOP;
	cmd->len =  (cmd->len & (F_NOT | F_OR));

	/* Compute length of comment string. */
	for (i = 0, l = 0; av[i] != NULL; i++)
		l += strlen(av[i]) + 1;
	if (l == 0)
		return;
	if (l > 84)
		errx(EX_DATAERR,
		    "comment too long (max 80 chars)");
	l = 1 + (l+3)/4;
	cmd->len =  (cmd->len & (F_NOT | F_OR)) | l;
	for (i = 0; av[i] != NULL; i++) {
		strcpy(p, av[i]);
		p += strlen(av[i]);
		*p++ = ' ';
	}
	*(--p) = '\0';
}
/*
 * A function to fill simple commands of size 1.
 * Existing flags are preserved.
 */
static void
fill_cmd(ipfw_insn *cmd, enum ipfw_opcodes opcode, int flags, uint16_t arg)
{
	cmd->opcode = opcode;
	cmd->len =  ((cmd->len | flags) & (F_NOT | F_OR)) | 1;
	cmd->arg1 = arg;
}

/*
 * conditionally runs the command.
 * Selected options or negative -> getsockopt
 */
int
do_cmd(int optname, void *optval, /*uintptr_t*/ int  optlen)
{
	static int s = -1;	/* the socket */
	int i;

	if (co.test_only)
		return 0;

	if (s == -1)
		s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	/*if (s < 0)
		err(EX_UNAVAILABLE, "socket");
*/
	if (optname == IP_FW_GET || optname == IP_DUMMYNET_GET ||
	    optname == IP_FW_ADD || optname == IP_FW_TABLE_LIST ||
	    optname == IP_FW_TABLE_GETSIZE ||
	    optname == IP_FW_NAT_GET_CONFIG ||
	    optname < 0 ||
	    optname == IP_FW_NAT_GET_LOG) {
		if (optname < 0)
			optname = -optname;
		i = getsockopt(s, IPPROTO_IP, optname, optval,
			(socklen_t *)&optlen);
	} else {
		i = setsockopt(s, IPPROTO_IP, optname, optval, &optlen);
	}
	return i;
}
/**
 * match_token takes a table and a string, returns the value associated
 * with the string (-1 in case of failure).
 */
int
match_token(struct _s_x *table, char *string)
{
	struct _s_x *pt;
	unsigned int  i = strlen(string);

	for (pt = table ; i && pt->s != NULL ; pt++)
		if (strlen(pt->s) == i && !bcmp(string, pt->s, i))
			return pt->x;
	return -1;
}
/*
 * _substrcmp takes two strings and returns 1 if they do not match,
 * and 0 if they match exactly or the first string is a sub-string
 * of the second.  A warning is printed to stderr in the case that the
 * first string is a sub-string of the second.
 *
 * This function will be removed in the future through the usual
 * deprecation process.
 */


/**
 * match_value takes a table and a value, returns the string associated
 * with the value (NULL in case of failure).
 */
char const *
match_value(struct _s_x *p, int value)
{
	for (; p->s != NULL; p++)
		if (p->x == value)
			return p->s;
	return NULL;
}

int
_substrcmp(const char *str1, const char* str2)
{

	if (strncmp(str1, str2, strlen(str1)) != 0)
		return 1;

	/*if (strlen(str1) != strlen(str2))
		warnx("DEPRECATED: '%s' matched '%s' as a sub-string",
		    str1, str2);*/
	return 0;
}

static int
lookup_host (char *host, struct in_addr *ipaddr)
{
	struct hostent *he;

	if (!inet_aton(host, ipaddr)) {
		if ((he = gethostbyname(host)) == NULL)
			return(-1);
		*ipaddr = *(struct in_addr *)he->h_addr_list[0];
	}
	return(0);
}

/*
 * fills the addr and mask fields in the instruction as appropriate from av.
 * Update length as appropriate.
 * The following formats are allowed:
 *	me	returns O_IP_*_ME
 *	1.2.3.4		single IP address
 *	1.2.3.4:5.6.7.8	address:mask
 *	1.2.3.4/24	address/mask
 *	1.2.3.4/26{1,6,5,4,23}	set of addresses in a subnet
 * We can have multiple comma-separated address/mask entries.
 */
static void
fill_ip(ipfw_insn_ip *cmd, char *av)
{
	int len = 0;
	uint32_t *d = ((ipfw_insn_u32 *)cmd)->d;

	cmd->o.len &= ~F_LEN_MASK;	/* zero len */

	if (_substrcmp(av, "any") == 0)
		return;

	if (_substrcmp(av, "me") == 0) {
		cmd->o.len |= F_INSN_SIZE(ipfw_insn);
		return;
	}

	if (strncmp(av, "table(", 6) == 0) {
		char *p = strchr(av + 6, ',');

		if (p)
			*p++ = '\0';
		cmd->o.opcode = O_IP_DST_LOOKUP;
		cmd->o.arg1 = strtoul(av + 6, NULL, 0);
		if (p) {
			cmd->o.len |= F_INSN_SIZE(ipfw_insn_u32);
			d[0] = strtoul(p, NULL, 0);
		} else
			cmd->o.len |= F_INSN_SIZE(ipfw_insn);
		return;
	}

    while (av) {
	/*
	 * After the address we can have '/' or ':' indicating a mask,
	 * ',' indicating another address follows, '{' indicating a
	 * set of addresses of unspecified size.
	 */
	char *t = NULL, *p = strpbrk(av, "/:,{");
	int masklen;
	char md, nd = '\0';

	if (p) {
		md = *p;
		*p++ = '\0';
		if ((t = strpbrk(p, ",{")) != NULL) {
			nd = *t;
			*t = '\0';
		}
	} else
		md = '\0';

	if (lookup_host(av, (struct in_addr *)&d[0]) != 0)
		errx(EX_NOHOST, "hostname ``%s'' unknown", av);
	switch (md) {
	case ':':
		if (!inet_aton(p, (struct in_addr *)&d[1]))
			errx(EX_DATAERR, "bad netmask ``%s''", p);
		break;
	case '/':
		masklen = atoi(p);
		if (masklen == 0)
			d[1] = htonl(0);	/* mask */
		else if (masklen > 32)
			errx(EX_DATAERR, "bad width ``%s''", p);
		else
			d[1] = htonl(~0 << (32 - masklen));
		break;
	case '{':	/* no mask, assume /24 and put back the '{' */
		d[1] = htonl(~0 << (32 - 24));
		*(--p) = md;
		break;

	case ',':	/* single address plus continuation */
		*(--p) = md;
		/* FALLTHROUGH */
	case 0:		/* initialization value */
	default:
		d[1] = htonl(~0);	/* force /32 */
		break;
	}
	d[0] &= d[1];		/* mask base address with mask */
	if (t)
		*t = nd;
	/* find next separator */
	if (p)
		p = strpbrk(p, ",{");
	if (p && *p == '{') {
		/*
		 * We have a set of addresses. They are stored as follows:
		 *   arg1	is the set size (powers of 2, 2..256)
		 *   addr	is the base address IN HOST FORMAT
		 *   mask..	is an array of arg1 bits (rounded up to
		 *		the next multiple of 32) with bits set
		 *		for each host in the map.
		 */
		uint32_t *map = (uint32_t *)&cmd->mask;
		int low, high;
		int i = contigmask((uint8_t *)&(d[1]), 32);

		if (len > 0)
			errx(EX_DATAERR, "address set cannot be in a list");
		if (i < 24 || i > 31)
			errx(EX_DATAERR, "invalid set with mask %d\n", i);
		cmd->o.arg1 = 1<<(32-i);	/* map length		*/
		d[0] = ntohl(d[0]);		/* base addr in host format */
		cmd->o.opcode = O_IP_DST_SET;	/* default */
		cmd->o.len |= F_INSN_SIZE(ipfw_insn_u32) + (cmd->o.arg1+31)/32;
		for (i = 0; i < (cmd->o.arg1+31)/32 ; i++)
			map[i] = 0;	/* clear map */

		av = p + 1;
		low = d[0] & 0xff;
		high = low + cmd->o.arg1 - 1;
		/*
		 * Here, i stores the previous value when we specify a range
		 * of addresses within a mask, e.g. 45-63. i = -1 means we
		 * have no previous value.
		 */
		i = -1;	/* previous value in a range */
		while (isdigit(*av)) {
			char *s;
			int a = strtol(av, &s, 0);

			if (s == av) { /* no parameter */
			    if (*av != '}')
				errx(EX_DATAERR, "set not closed\n");
			    if (i != -1)
				errx(EX_DATAERR, "incomplete range %d-", i);
			    break;
			}
			if (a < low || a > high)
			    errx(EX_DATAERR, "addr %d out of range [%d-%d]\n",
				a, low, high);
			a -= low;
			if (i == -1)	/* no previous in range */
			    i = a;
			else {		/* check that range is valid */
			    if (i > a)
				errx(EX_DATAERR, "invalid range %d-%d",
					i+low, a+low);
			    if (*s == '-')
				errx(EX_DATAERR, "double '-' in range");
			}
			for (; i <= a; i++)
			    map[i/32] |= 1<<(i & 31);
			i = -1;
			if (*s == '-')
			    i = a;
			else if (*s == '}')
			    break;
			av = s+1;
		}
		return;
	}
	av = p;
	if (av)			/* then *av must be a ',' */
		av++;

	/* Check this entry */
	if (d[1] == 0) { /* "any", specified as x.x.x.x/0 */
		/*
		 * 'any' turns the entire list into a NOP.
		 * 'not any' never matches, so it is removed from the
		 * list unless it is the only item, in which case we
		 * report an error.
		 */
		if (cmd->o.len & F_NOT) {	/* "not any" never matches */
			if (av == NULL && len == 0) /* only this entry */
				errx(EX_DATAERR, "not any never matches");
		}
		/* else do nothing and skip this entry */
		return;
	}
	/* A single IP can be stored in an optimized format */
	if (d[1] == (uint32_t)~0 && av == NULL && len == 0) {
		cmd->o.len |= F_INSN_SIZE(ipfw_insn_u32);
		return;
	}
	len += 2;	/* two words... */
	d += 2;
    } /* end while */
    if (len + 1 > F_LEN_MASK)
	errx(EX_DATAERR, "address list too long");
    cmd->o.len |= len+1;
}

/*
 * helper function to process a set of flags and set bits in the
 * appropriate masks.
 */
static void
fill_flags(ipfw_insn *cmd, enum ipfw_opcodes opcode,
	struct _s_x *flags, char *p)
{
	uint8_t set=0, clear=0;

	while (p && *p) {
		char *q;	/* points to the separator */
		int val;
		uint8_t *which;	/* mask we are working on */

		if (*p == '!') {
			p++;
			which = &clear;
		} else
			which = &set;
		q = strchr(p, ',');
		if (q)
			*q++ = '\0';
		val = match_token(flags, p);
		if (val <= 0)
			errx(EX_DATAERR, "invalid flag %s", p);
		*which |= (uint8_t)val;
		p = q;
	}
        cmd->opcode = opcode;
        cmd->len =  (cmd->len & (F_NOT | F_OR)) | 1;
        cmd->arg1 = (set & 0xff) | ( (clear & 0xff) << 8);
}


/*
 * Like strtol, but also translates service names into port numbers
 * for some protocols.
 * In particular:
 *	proto == -1 disables the protocol check;
 *	proto == IPPROTO_ETHERTYPE looks up an internal table
 *	proto == <some value in /etc/protocols> matches the values there.
 * Returns *end == s in case the parameter is not found.
 */
static int
strtoport(char *s, char **end, int base, int proto)
{
	char *p, *buf;
	char *s1;
	int i;

	*end = s;		/* default - not found */
	if (*s == '\0')
		return 0;	/* not found */

	if (isdigit(*s))
		return strtol(s, end, base);

	/*
	 * find separator. '\\' escapes the next char.
	 */
	for (s1 = s; *s1 && (isalnum(*s1) || *s1 == '\\') ; s1++)
		if (*s1 == '\\' && s1[1] != '\0')
			s1++;

	buf = safe_calloc(s1 - s + 1, 1);

	/*
	 * copy into a buffer skipping backslashes
	 */
	for (p = s, i = 0; p != s1 ; p++)
		if (*p != '\\')
			buf[i++] = *p;
	buf[i++] = '\0';

	if (proto == IPPROTO_ETHERTYPE) {
		i = match_token(ether_types, buf);
		free(buf, M_IPFW);
		if (i != -1) {	/* found */
			*end = s1;
			return i;
		}
	} else {
		struct protoent *pe = NULL;
		struct servent *se;

		if (proto != 0)
			pe = getprotobynumber(proto);
		//setservent(1); Achtung!
		se = getservbyname(buf, pe ? pe->p_name : NULL);
		free(buf, M_IPFW);
		if (se != NULL) {
			*end = s1;
			return ntohs(se->s_port);
		}
	}
	return 0;	/* not found */
}


/*
 * Fill the body of the command with the list of port ranges.
 */
static int
fill_newports(ipfw_insn_u16 *cmd, char *av, int proto)
{
	uint16_t a, b, *p = cmd->ports;
	int i = 0;
	char *s = av;

	while (*s) {
		a = strtoport(av, &s, 0, proto);
		if (s == av) 			/* empty or invalid argument */
			return (0);

		switch (*s) {
		case '-':			/* a range */
			av = s + 1;
			b = strtoport(av, &s, 0, proto);
			/* Reject expressions like '1-abc' or '1-2-3'. */
			if (s == av || (*s != ',' && *s != '\0'))
				return (0);
			p[0] = a;
			p[1] = b;
			break;
		case ',':			/* comma separated list */
		case '\0':
			p[0] = p[1] = a;
			break;
		default:
			/*warnx("port list: invalid separator <%c> in <%s>",
				*s, av);*/
			return (0);
		}

		i++;
		p += 2;
		av = s + 1;
	}
	if (i > 0) {
		if (i + 1 > F_LEN_MASK)
			errx(EX_DATAERR, "too many ports/ranges\n");
		cmd->o.len |= i + 1;	/* leave F_NOT and F_OR untouched */
	}
	return (i);
}

/*
 * Fetch and add the MAC address and type, with masks. This generates one or
 * two microinstructions, and returns the pointer to the last one.
 */
static ipfw_insn *
add_mac(ipfw_insn *cmd, char *av[])
{
	ipfw_insn_mac *mac;

	if ( ( av[0] == NULL ) || ( av[1] == NULL ) )
		errx(EX_DATAERR, "MAC dst src");

	cmd->opcode = O_MACADDR2;
	cmd->len = (cmd->len & (F_NOT | F_OR)) | F_INSN_SIZE(ipfw_insn_mac);

	mac = (ipfw_insn_mac *)cmd;
	get_mac_addr_mask(av[0], mac->addr, mac->mask);	/* dst */
	get_mac_addr_mask(av[1], &(mac->addr[ETHER_ADDR_LEN]),
	    &(mac->mask[ETHER_ADDR_LEN])); /* src */
	return cmd;
}

static ipfw_insn *
add_mactype(ipfw_insn *cmd, char *av)
{
	if (!av)
		errx(EX_DATAERR, "missing MAC type");
	if (strcmp(av, "any") != 0) { /* we have a non-null type */
		fill_newports((ipfw_insn_u16 *)cmd, av, IPPROTO_ETHERTYPE);
		cmd->opcode = O_MAC_TYPE;
		return cmd;
	} else
		return NULL;
}
static ipfw_insn *
add_proto0(ipfw_insn *cmd, char *av, u_char *protop)
{
	struct protoent *pe;
	char *ep;
	int proto;

	proto = strtol(av, &ep, 10);
	if (*ep != '\0' || proto <= 0) {
		if ((pe = getprotobyname(av)) == NULL)
			return NULL;
		proto = pe->p_proto;
	}

	fill_cmd(cmd, O_PROTO, 0, proto);
	*protop = proto;
	return cmd;
}

static ipfw_insn *
add_proto(ipfw_insn *cmd, char *av, u_char *protop)
{
	u_char proto = IPPROTO_IP;

	if (_substrcmp(av, "all") == 0 || strcmp(av, "ip") == 0)
		; /* do not set O_IP4 nor O_IP6 */
	else if (strcmp(av, "ip4") == 0)
		/* explicit "just IPv4" rule */
		fill_cmd(cmd, O_IP4, 0, 0);
	else if (strcmp(av, "ip6") == 0) {
		/* explicit "just IPv6" rule */
		proto = IPPROTO_IPV6;
		fill_cmd(cmd, O_IP6, 0, 0);
	} else
		return add_proto0(cmd, av, protop);

	*protop = proto;
	return cmd;
}

static ipfw_insn *
add_proto_compat(ipfw_insn *cmd, char *av, u_char *protop)
{
	u_char proto = IPPROTO_IP;

	if (_substrcmp(av, "all") == 0 || strcmp(av, "ip") == 0)
		; /* do not set O_IP4 nor O_IP6 */
	else if (strcmp(av, "ipv4") == 0 || strcmp(av, "ip4") == 0)
		/* explicit "just IPv4" rule */
		fill_cmd(cmd, O_IP4, 0, 0);
	else if (strcmp(av, "ipv6") == 0 || strcmp(av, "ip6") == 0) {
		/* explicit "just IPv6" rule */
		proto = IPPROTO_IPV6;
		fill_cmd(cmd, O_IP6, 0, 0);
	} else
		return add_proto0(cmd, av, protop);

	*protop = proto;
	return cmd;
}

static ipfw_insn *
add_srcip(ipfw_insn *cmd, char *av)
{
	fill_ip((ipfw_insn_ip *)cmd, av);
	if (cmd->opcode == O_IP_DST_SET)			/* set */
		cmd->opcode = O_IP_SRC_SET;
	else if (cmd->opcode == O_IP_DST_LOOKUP)		/* table */
		cmd->opcode = O_IP_SRC_LOOKUP;
	else if (F_LEN(cmd) == F_INSN_SIZE(ipfw_insn))		/* me */
		cmd->opcode = O_IP_SRC_ME;
	else if (F_LEN(cmd) == F_INSN_SIZE(ipfw_insn_u32))	/* one IP */
		cmd->opcode = O_IP_SRC;
	else							/* addr/mask */
		cmd->opcode = O_IP_SRC_MASK;
	return cmd;
}

static ipfw_insn *
add_dstip(ipfw_insn *cmd, char *av)
{
	fill_ip((ipfw_insn_ip *)cmd, av);
	if (cmd->opcode == O_IP_DST_SET)			/* set */
		;
	else if (cmd->opcode == O_IP_DST_LOOKUP)		/* table */
		;
	else if (F_LEN(cmd) == F_INSN_SIZE(ipfw_insn))		/* me */
		cmd->opcode = O_IP_DST_ME;
	else if (F_LEN(cmd) == F_INSN_SIZE(ipfw_insn_u32))	/* one IP */
		cmd->opcode = O_IP_DST;
	else							/* addr/mask */
		cmd->opcode = O_IP_DST_MASK;
	return cmd;
}

static ipfw_insn *
add_ports(ipfw_insn *cmd, char *av, u_char proto, int opcode)
{
	/* XXX "any" is trapped before. Perhaps "to" */
	if (_substrcmp(av, "any") == 0) {
		return NULL;
	} else if (fill_newports((ipfw_insn_u16 *)cmd, av, proto)) {
		/* XXX todo: check that we have a protocol with ports */
		cmd->opcode = opcode;
		return cmd;
	}
	return NULL;
}

static ipfw_insn *
add_src(ipfw_insn *cmd, char *av, u_char proto)
{
	struct in6_addr a;
	char *host, *ch;
	ipfw_insn *ret = NULL;

	if ((host = strdup(av)) == NULL)
		return NULL;
	if ((ch = strrchr(host, '/')) != NULL)
		*ch = '\0';

	/*if (proto == IPPROTO_IPV6  || strcmp(av, "me6") == 0 ||
	    inet_pton(AF_INET6, host, &a) == 1)
		ret = add_srcip6(cmd, av);
	/* XXX: should check for IPv4, not !IPv6 */
	if (ret == NULL && (proto == IPPROTO_IP || strcmp(av, "me") == 0 ||
	    inet_pton(AF_INET6, host, &a) != 1))
		ret = add_srcip(cmd, av);
	if (ret == NULL && strcmp(av, "any") != 0)
		ret = cmd;

	free(host, M_IPFW);
	return ret;
}

static ipfw_insn *
add_dst(ipfw_insn *cmd, char *av, u_char proto)
{
	struct in6_addr a;
	char *host, *ch;
	ipfw_insn *ret = NULL;

	if ((host = strdup(av)) == NULL)
		return NULL;
	if ((ch = strrchr(host, '/')) != NULL)
		*ch = '\0';

	/*if (proto == IPPROTO_IPV6  || strcmp(av, "me6") == 0 ||
	    inet_pton(AF_INET6, host, &a) == 1)
		ret = add_dstip6(cmd, av);*/
	/* XXX: should check for IPv4, not !IPv6 */
	if (ret == NULL && (proto == IPPROTO_IP || strcmp(av, "me") == 0 ||
	    inet_pton(AF_INET6, host, &a) != 1))
		ret = add_dstip(cmd, av);
	if (ret == NULL && strcmp(av, "any") != 0)
		ret = cmd;

	free(host, M_IPFW);
	return ret;
}

/*
 * Parse arguments and assemble the microinstructions which make up a rule.
 * Rules are added into the 'rulebuf' and then copied in the correct order
 * into the actual rule.
 *
 * The syntax for a rule starts with the action, followed by
 * optional action parameters, and the various match patterns.
 * In the assembled microcode, the first opcode must be an O_PROBE_STATE
 * (generated if the rule includes a keep-state option), then the
 * various match patterns, log/altq actions, and the actual action.
 *
 */
void
ipfw_add(char *av[])
{
	/*
	 * rules are added into the 'rulebuf' and then copied in
	 * the correct order into the actual rule.
	 * Some things that need to go out of order (prob, action etc.)
	 * go into actbuf[].
	 */
	static uint32_t rulebuf[255], actbuf[255], cmdbuf[255];

	ipfw_insn *src, *dst, *cmd, *action, *prev=NULL;
	ipfw_insn *first_cmd;	/* first match pattern */

	struct ip_fw *rule;

	/*
	 * various flags used to record that we entered some fields.
	 */
	ipfw_insn *have_state = NULL;	/* check-state or keep-state */
	ipfw_insn *have_log = NULL, *have_altq = NULL, *have_tag = NULL;
	size_t len;

	int i;

	int open_par = 0;	/* open parenthesis ( */

	/* proto is here because it is used to fetch ports */
	u_char proto = IPPROTO_IP;	/* default protocol */

	double match_prob = 1; /* match probability, default is always match */

	bzero(actbuf, sizeof(actbuf));		/* actions go here */
	bzero(cmdbuf, sizeof(cmdbuf));
	bzero(rulebuf, sizeof(rulebuf));

	rule = (struct ip_fw *)rulebuf;
	cmd = (ipfw_insn *)cmdbuf;
	action = (ipfw_insn *)actbuf;

	av++;

	/* [rule N]	-- Rule number optional */
	if (av[0] && isdigit(**av)) {
		rule->rulenum = atoi(*av);
		av++;
	}

	/* [set N]	-- set number (0..RESVD_SET), optional */
	if (av[0] && av[1] && _substrcmp(*av, "set") == 0) {
		int set = strtoul(av[1], NULL, 10);
		if (set < 0 || set > RESVD_SET)
			errx(EX_DATAERR, "illegal set %s", av[1]);
		rule->set = set;
		av += 2;
	}

	/* [prob D]	-- match probability, optional */
	if (av[0] && av[1] && _substrcmp(*av, "prob") == 0) {
		match_prob = strtod(av[1], NULL);

		if (match_prob <= 0 || match_prob > 1)
			errx(EX_DATAERR, "illegal match prob. %s", av[1]);
		av += 2;
	}

	/* action	-- mandatory */
	NEED1("missing action");
	i = match_token(rule_actions, *av);
	av++;
	action->len = 1;	/* default */
	switch(i) {
	case TOK_CHECKSTATE:
		have_state = action;
		action->opcode = O_CHECK_STATE;
		break;

	case TOK_ACCEPT:
		action->opcode = O_ACCEPT;
		break;

	case TOK_DENY:
		action->opcode = O_DENY;
		action->arg1 = 0;
		break;

	case TOK_REJECT:
		action->opcode = O_REJECT;
		action->arg1 = ICMP_UNREACH_HOST;
		break;

	case TOK_RESET:
		action->opcode = O_REJECT;
		action->arg1 = ICMP_REJECT_RST;
		break;

	case TOK_RESET6:
		action->opcode = O_UNREACH6;
		action->arg1 = ICMP6_UNREACH_RST;
		break;

	case TOK_UNREACH:
		action->opcode = O_REJECT;
		NEED1("missing reject code");
		fill_reject_code(&action->arg1, *av);
		av++;
		break;

	/*case TOK_UNREACH6:
		action->opcode = O_UNREACH6;
		NEED1("missing unreach code");
		fill_unreach6_code(&action->arg1, *av);
		av++;
		break;
*/
	case TOK_COUNT:
		action->opcode = O_COUNT;
		break;

	case TOK_NAT:
 		action->opcode = O_NAT;
 		action->len = F_INSN_SIZE(ipfw_insn_nat);
		goto chkarg;

	case TOK_QUEUE:
		action->opcode = O_QUEUE;
		goto chkarg;
	case TOK_PIPE:
		action->opcode = O_PIPE;
		goto chkarg;
	case TOK_SKIPTO:
		action->opcode = O_SKIPTO;
		goto chkarg;
	case TOK_NETGRAPH:
		action->opcode = O_NETGRAPH;
		goto chkarg;
	case TOK_NGTEE:
		action->opcode = O_NGTEE;
		goto chkarg;
	case TOK_DIVERT:
		action->opcode = O_DIVERT;
		goto chkarg;
	case TOK_TEE:
		action->opcode = O_TEE;
chkarg:
		if (!av[0])
			errx(EX_USAGE, "missing argument for %s", *(av - 1));
		if (isdigit(**av)) {
			action->arg1 = strtoul(*av, NULL, 10);
			if (action->arg1 <= 0 || action->arg1 >= IP_FW_TABLEARG)
				errx(EX_DATAERR, "illegal argument for %s",
				    *(av - 1));
		} else if (_substrcmp(*av, "tablearg") == 0) {
			action->arg1 = IP_FW_TABLEARG;
		} else if (i == TOK_DIVERT || i == TOK_TEE) {
			struct servent *s;
			//setservent(1); Achtung!
			s = getservbyname(av[0], "divert");
			if (s != NULL)
				action->arg1 = ntohs(s->s_port);
			else
				errx(EX_DATAERR, "illegal divert/tee port");
		} else
			errx(EX_DATAERR, "illegal argument for %s", *(av - 1));
		av++;
		break;

	case TOK_FORWARD: {
		ipfw_insn_sa *p = (ipfw_insn_sa *)action;
		char *s, *end;

		NEED1("missing forward address[:port]");

		action->opcode = O_FORWARD_IP;
		action->len = F_INSN_SIZE(ipfw_insn_sa);

		/*
		 * In the kernel we assume AF_INET and use only
		 * sin_port and sin_addr. Remember to set sin_len as
		 * the routing code seems to use it too.
		 */
		p->sa.sin_family = AF_INET;
		p->sa.sin_len = sizeof(struct sockaddr_in);
		p->sa.sin_port = 0;
		/*
		 * locate the address-port separator (':' or ',')
		 */
		s = strchr(*av, ':');
		if (s == NULL)
			s = strchr(*av, ',');
		if (s != NULL) {
			*(s++) = '\0';
			i = strtoport(s, &end, 0 /* base */, 0 /* proto */);
			if (s == end)
				errx(EX_DATAERR,
				    "illegal forwarding port ``%s''", s);
			p->sa.sin_port = (u_short)i;
		}
		if (_substrcmp(*av, "tablearg") == 0)
			p->sa.sin_addr.s_addr = INADDR_ANY;
		else
			lookup_host(*av, &(p->sa.sin_addr));
		av++;
		break;
	    }
	case TOK_COMMENT:
		/* pretend it is a 'count' rule followed by the comment */
		action->opcode = O_COUNT;
		av--;		/* go back... */
		break;

	/*case TOK_SETFIB:
	    {
		int numfibs;
		size_t intsize = sizeof(int);

		action->opcode = O_SETFIB;
 		NEED1("missing fib number");
 	        action->arg1 = strtoul(*av, NULL, 10);
		if (sysctlbyname("net.fibs", &numfibs, &intsize, NULL, 0) == -1)
			errx(EX_DATAERR, "fibs not suported.\n");
		if (action->arg1 >= numfibs)  
			errx(EX_DATAERR, "fib too large.\n");
 		av++;
 		break;
	    }*/

	case TOK_REASS:
		action->opcode = O_REASS;
		break;

	default:
		errx(EX_DATAERR, "invalid action %s\n", av[-1]);
	}
	action = next_cmd(action);

	/*
	 * [altq queuename] -- altq tag, optional
	 * [log [logamount N]]	-- log, optional
	 *
	 * If they exist, it go first in the cmdbuf, but then it is
	 * skipped in the copy section to the end of the buffer.
	 */
	while (av[0] != NULL && (i = match_token(rule_action_params, *av)) != -1) {
		av++;
		switch (i) {
		case TOK_LOG:
		    {
			ipfw_insn_log *c = (ipfw_insn_log *)cmd;
			int l;

			if (have_log)
				errx(EX_DATAERR,
				    "log cannot be specified more than once");
			have_log = (ipfw_insn *)c;
			cmd->len = F_INSN_SIZE(ipfw_insn_log);
			cmd->opcode = O_LOG;
			if (av[0] && _substrcmp(*av, "logamount") == 0) {
				av++;
				NEED1("logamount requires argument");
				l = atoi(*av);
				if (l < 0)
					errx(EX_DATAERR,
					    "logamount must be positive");
				c->max_log = l;
				av++;
			} else {
				len = sizeof(c->max_log);
				/*if (sysctlbyname("net.inet.ip.fw.verbose_limit",
				    &c->max_log, &len, NULL, 0) == -1)
					errx(1, "sysctlbyname(\"%s\")",
					    "net.inet.ip.fw.verbose_limit");*/
			}
		    }
			break;
/*
#ifndef NO_ALTQ
		case TOK_ALTQ:
		    {
			ipfw_insn_altq *a = (ipfw_insn_altq *)cmd;

			NEED1("missing altq queue name");
			if (have_altq)
				errx(EX_DATAERR,
				    "altq cannot be specified more than once");
			have_altq = (ipfw_insn *)a;
			cmd->len = F_INSN_SIZE(ipfw_insn_altq);
			cmd->opcode = O_ALTQ;
			a->qid = altq_name_to_qid(*av);
			av++;
		    }
			break;
#endif*/

		case TOK_TAG:
		case TOK_UNTAG: {
			uint16_t tag;

			if (have_tag)
				errx(EX_USAGE, "tag and untag cannot be "
				    "specified more than once");
			GET_UINT_ARG(tag, IPFW_ARG_MIN, IPFW_ARG_MAX, i,
			   rule_action_params);
			have_tag = cmd;
			fill_cmd(cmd, O_TAG, (i == TOK_TAG) ? 0: F_NOT, tag);
			av++;
			break;
		}

		default:
			abort();
		}
		cmd = next_cmd(cmd);
	}

	if (have_state)	/* must be a check-state, we are done */
		goto done;

#define OR_START(target)					\
	if (av[0] && (*av[0] == '(' || *av[0] == '{')) { 	\
		if (open_par)					\
			errx(EX_USAGE, "nested \"(\" not allowed\n"); \
		prev = NULL;					\
		open_par = 1;					\
		if ( (av[0])[1] == '\0') {			\
			av++;					\
		} else						\
			(*av)++;				\
	}							\
	target:							\


#define	CLOSE_PAR						\
	if (open_par) {						\
		if (av[0] && (					\
		    strcmp(*av, ")") == 0 ||			\
		    strcmp(*av, "}") == 0)) {			\
			prev = NULL;				\
			open_par = 0;				\
			av++;					\
		} else						\
			errx(EX_USAGE, "missing \")\"\n");	\
	}

#define NOT_BLOCK						\
	if (av[0] && _substrcmp(*av, "not") == 0) {		\
		if (cmd->len & F_NOT)				\
			errx(EX_USAGE, "double \"not\" not allowed\n"); \
		cmd->len |= F_NOT;				\
		av++;						\
	}

#define OR_BLOCK(target)					\
	if (av[0] && _substrcmp(*av, "or") == 0) {		\
		if (prev == NULL || open_par == 0)		\
			errx(EX_DATAERR, "invalid OR block");	\
		prev->len |= F_OR;				\
		av++;					\
		goto target;					\
	}							\
	CLOSE_PAR;

	first_cmd = cmd;

#if 0
	/*
	 * MAC addresses, optional.
	 * If we have this, we skip the part "proto from src to dst"
	 * and jump straight to the option parsing.
	 */
	NOT_BLOCK;
	NEED1("missing protocol");
	if (_substrcmp(*av, "MAC") == 0 ||
	    _substrcmp(*av, "mac") == 0) {
		av++;			/* the "MAC" keyword */
		add_mac(cmd, av);	/* exits in case of errors */
		cmd = next_cmd(cmd);
		av += 2;		/* dst-mac and src-mac */
		NOT_BLOCK;
		NEED1("missing mac type");
		if (add_mactype(cmd, av[0]))
			cmd = next_cmd(cmd);
		av++;			/* any or mac-type */
		goto read_options;
	}
#endif

	/*
	 * protocol, mandatory
	 */
    OR_START(get_proto);
	NOT_BLOCK;
	NEED1("missing protocol");
	if (add_proto_compat(cmd, *av, &proto)) {
		av++;
		if (F_LEN(cmd) != 0) {
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	} else if (first_cmd != cmd) {
		errx(EX_DATAERR, "invalid protocol ``%s''", *av);
	} else
		goto read_options;
    OR_BLOCK(get_proto);

	/*
	 * "from", mandatory
	 */
	if ((av[0] == NULL) || _substrcmp(*av, "from") != 0)
		errx(EX_USAGE, "missing ``from''");
	av++;

	/*
	 * source IP, mandatory
	 */
    OR_START(source_ip);
	NOT_BLOCK;	/* optional "not" */
	NEED1("missing source address");
	if (add_src(cmd, *av, proto)) {
		av++;
		if (F_LEN(cmd) != 0) {	/* ! any */
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	} else
		errx(EX_USAGE, "bad source address %s", *av);
    OR_BLOCK(source_ip);

	/*
	 * source ports, optional
	 */
	NOT_BLOCK;	/* optional "not" */
	if ( av[0] != NULL ) {
		if (_substrcmp(*av, "any") == 0 ||
		    add_ports(cmd, *av, proto, O_IP_SRCPORT)) {
			av++;
			if (F_LEN(cmd) != 0)
				cmd = next_cmd(cmd);
		}
	}

	/*
	 * "to", mandatory
	 */
	if ( (av[0] == NULL) || _substrcmp(*av, "to") != 0 )
		errx(EX_USAGE, "missing ``to''");
	av++;

	/*
	 * destination, mandatory
	 */
    OR_START(dest_ip);
	NOT_BLOCK;	/* optional "not" */
	NEED1("missing dst address");
	if (add_dst(cmd, *av, proto)) {
		av++;
		if (F_LEN(cmd) != 0) {	/* ! any */
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	} else
		errx( EX_USAGE, "bad destination address %s", *av);
    OR_BLOCK(dest_ip);

	/*
	 * dest. ports, optional
	 */
	NOT_BLOCK;	/* optional "not" */
	if (av[0]) {
		if (_substrcmp(*av, "any") == 0 ||
		    add_ports(cmd, *av, proto, O_IP_DSTPORT)) {
			av++;
			if (F_LEN(cmd) != 0)
				cmd = next_cmd(cmd);
		}
	}

read_options:
	if (av[0] && first_cmd == cmd) {
		/*
		 * nothing specified so far, store in the rule to ease
		 * printout later.
		 */
		 rule->_pad = 1;
	}
	prev = NULL;
	while ( av[0] != NULL ) {
		char *s;
		ipfw_insn_u32 *cmd32;	/* alias for cmd */

		s = *av;
		cmd32 = (ipfw_insn_u32 *)cmd;

		if (*s == '!') {	/* alternate syntax for NOT */
			if (cmd->len & F_NOT)
				errx(EX_USAGE, "double \"not\" not allowed\n");
			cmd->len = F_NOT;
			s++;
		}
		i = match_token(rule_options, s);
		av++;
		switch(i) {
		case TOK_NOT:
			if (cmd->len & F_NOT)
				errx(EX_USAGE, "double \"not\" not allowed\n");
			cmd->len = F_NOT;
			break;

		case TOK_OR:
			if (open_par == 0 || prev == NULL)
				errx(EX_USAGE, "invalid \"or\" block\n");
			prev->len |= F_OR;
			break;

		case TOK_STARTBRACE:
			if (open_par)
				errx(EX_USAGE, "+nested \"(\" not allowed\n");
			open_par = 1;
			break;

		case TOK_ENDBRACE:
			if (!open_par)
				errx(EX_USAGE, "+missing \")\"\n");
			open_par = 0;
			prev = NULL;
        		break;

		case TOK_IN:
			fill_cmd(cmd, O_IN, 0, 0);
			break;

		case TOK_OUT:
			cmd->len ^= F_NOT; /* toggle F_NOT */
			fill_cmd(cmd, O_IN, 0, 0);
			break;

		case TOK_DIVERTED:
			fill_cmd(cmd, O_DIVERTED, 0, 3);
			break;

		case TOK_DIVERTEDLOOPBACK:
			fill_cmd(cmd, O_DIVERTED, 0, 1);
			break;

		case TOK_DIVERTEDOUTPUT:
			fill_cmd(cmd, O_DIVERTED, 0, 2);
			break;

		case TOK_FRAG:
			fill_cmd(cmd, O_FRAG, 0, 0);
			break;

		case TOK_LAYER2:
			fill_cmd(cmd, O_LAYER2, 0, 0);
			break;

		case TOK_XMIT:
		case TOK_RECV:
		case TOK_VIA:
			NEED1("recv, xmit, via require interface name"
				" or address");
			fill_iface((ipfw_insn_if *)cmd, av[0]);
			av++;
			if (F_LEN(cmd) == 0)	/* not a valid address */
				break;
			if (i == TOK_XMIT)
				cmd->opcode = O_XMIT;
			else if (i == TOK_RECV)
				cmd->opcode = O_RECV;
			else if (i == TOK_VIA)
				cmd->opcode = O_VIA;
			break;

		case TOK_ICMPTYPES:
			NEED1("icmptypes requires list of types");
			fill_icmptypes((ipfw_insn_u32 *)cmd, *av);
			av++;
			break;

		/*case TOK_ICMP6TYPES:
			NEED1("icmptypes requires list of types");
			fill_icmp6types((ipfw_insn_icmp6 *)cmd, *av);
			av++;
			break;
*/
		case TOK_IPTTL:
			NEED1("ipttl requires TTL");
			if (strpbrk(*av, "-,")) {
			    if (!add_ports(cmd, *av, 0, O_IPTTL))
				errx(EX_DATAERR, "invalid ipttl %s", *av);
			} else
			    fill_cmd(cmd, O_IPTTL, 0, strtoul(*av, NULL, 0));
			av++;
			break;

		case TOK_IPID:
			NEED1("ipid requires id");
			if (strpbrk(*av, "-,")) {
			    if (!add_ports(cmd, *av, 0, O_IPID))
				errx(EX_DATAERR, "invalid ipid %s", *av);
			} else
			    fill_cmd(cmd, O_IPID, 0, strtoul(*av, NULL, 0));
			av++;
			break;

		case TOK_IPLEN:
			NEED1("iplen requires length");
			if (strpbrk(*av, "-,")) {
			    if (!add_ports(cmd, *av, 0, O_IPLEN))
				errx(EX_DATAERR, "invalid ip len %s", *av);
			} else
			    fill_cmd(cmd, O_IPLEN, 0, strtoul(*av, NULL, 0));
			av++;
			break;

		case TOK_IPVER:
			NEED1("ipver requires version");
			fill_cmd(cmd, O_IPVER, 0, strtoul(*av, NULL, 0));
			av++;
			break;

		case TOK_IPPRECEDENCE:
			NEED1("ipprecedence requires value");
			fill_cmd(cmd, O_IPPRECEDENCE, 0,
			    (strtoul(*av, NULL, 0) & 7) << 5);
			av++;
			break;

		case TOK_IPOPTS:
			NEED1("missing argument for ipoptions");
			fill_flags(cmd, O_IPOPT, f_ipopts, *av);
			av++;
			break;

		case TOK_IPTOS:
			NEED1("missing argument for iptos");
			fill_flags(cmd, O_IPTOS, f_iptos, *av);
			av++;
			break;

		/*case TOK_UID:
			NEED1("uid requires argument");
		    {
			char *end;
			uid_t uid;
			struct passwd *pwd;

			cmd->opcode = O_UID;
			uid = strtoul(*av, &end, 0);
			pwd = (*end == '\0') ? getpwuid(uid) : getpwnam(*av);
			if (pwd == NULL)
				errx(EX_DATAERR, "uid \"%s\" nonexistent", *av);
			cmd32->d[0] = pwd->pw_uid;
			cmd->len |= F_INSN_SIZE(ipfw_insn_u32);
			av++;
		    }
			break;

		case TOK_GID:
			NEED1("gid requires argument");
		    {
			char *end;
			gid_t gid;
			struct group *grp;

			cmd->opcode = O_GID;
			gid = strtoul(*av, &end, 0);
			grp = (*end == '\0') ? getgrgid(gid) : getgrnam(*av);
			if (grp == NULL)
				errx(EX_DATAERR, "gid \"%s\" nonexistent", *av);
			cmd32->d[0] = grp->gr_gid;
			cmd->len |= F_INSN_SIZE(ipfw_insn_u32);
			av++;
		    }
			break;
*/
		case TOK_JAIL:
			NEED1("jail requires argument");
		    {
			char *end;
			int jid;

			cmd->opcode = O_JAIL;
			jid = (int)strtol(*av, &end, 0);
			if (jid < 0 || *end != '\0')
				errx(EX_DATAERR, "jail requires prison ID");
			cmd32->d[0] = (uint32_t)jid;
			cmd->len |= F_INSN_SIZE(ipfw_insn_u32);
			av++;
		    }
			break;

		case TOK_ESTAB:
			fill_cmd(cmd, O_ESTAB, 0, 0);
			break;

		case TOK_SETUP:
			fill_cmd(cmd, O_TCPFLAGS, 0,
				(TH_SYN) | ( (TH_ACK) & 0xff) <<8 );
			break;

		case TOK_TCPDATALEN:
			NEED1("tcpdatalen requires length");
			if (strpbrk(*av, "-,")) {
			    if (!add_ports(cmd, *av, 0, O_TCPDATALEN))
				errx(EX_DATAERR, "invalid tcpdata len %s", *av);
			} else
			    fill_cmd(cmd, O_TCPDATALEN, 0,
				    strtoul(*av, NULL, 0));
			av++;
			break;

		case TOK_TCPOPTS:
			NEED1("missing argument for tcpoptions");
			fill_flags(cmd, O_TCPOPTS, f_tcpopts, *av);
			av++;
			break;

		case TOK_TCPSEQ:
		case TOK_TCPACK:
			NEED1("tcpseq/tcpack requires argument");
			cmd->len = F_INSN_SIZE(ipfw_insn_u32);
			cmd->opcode = (i == TOK_TCPSEQ) ? O_TCPSEQ : O_TCPACK;
			cmd32->d[0] = htonl(strtoul(*av, NULL, 0));
			av++;
			break;

		case TOK_TCPWIN:
			NEED1("tcpwin requires length");
			fill_cmd(cmd, O_TCPWIN, 0,
			    htons(strtoul(*av, NULL, 0)));
			av++;
			break;

		case TOK_TCPFLAGS:
			NEED1("missing argument for tcpflags");
			cmd->opcode = O_TCPFLAGS;
			fill_flags(cmd, O_TCPFLAGS, f_tcpflags, *av);
			av++;
			break;

		case TOK_KEEPSTATE:
			if (open_par)
				errx(EX_USAGE, "keep-state cannot be part "
				    "of an or block");
			if (have_state)
				errx(EX_USAGE, "only one of keep-state "
					"and limit is allowed");
			have_state = cmd;
			fill_cmd(cmd, O_KEEP_STATE, 0, 0);
			break;

		case TOK_LIMIT: {
			ipfw_insn_limit *c = (ipfw_insn_limit *)cmd;
			int val;

			if (open_par)
				errx(EX_USAGE,
				    "limit cannot be part of an or block");
			if (have_state)
				errx(EX_USAGE, "only one of keep-state and "
				    "limit is allowed");
			have_state = cmd;

			cmd->len = F_INSN_SIZE(ipfw_insn_limit);
			cmd->opcode = O_LIMIT;
			c->limit_mask = c->conn_limit = 0;

			while ( av[0] != NULL ) {
				if ((val = match_token(limit_masks, *av)) <= 0)
					break;
				c->limit_mask |= val;
				av++;
			}

			if (c->limit_mask == 0)
				errx(EX_USAGE, "limit: missing limit mask");

			GET_UINT_ARG(c->conn_limit, IPFW_ARG_MIN, IPFW_ARG_MAX,
			    TOK_LIMIT, rule_options);

			av++;
			break;
		}

		case TOK_PROTO:
			NEED1("missing protocol");
			if (add_proto(cmd, *av, &proto)) {
				av++;
			} else
				errx(EX_DATAERR, "invalid protocol ``%s''",
				    *av);
			break;

		case TOK_SRCIP:
			NEED1("missing source IP");
			if (add_srcip(cmd, *av)) {
				av++;
			}
			break;

		case TOK_DSTIP:
			NEED1("missing destination IP");
			if (add_dstip(cmd, *av)) {
				av++;
			}
			break;

		/*case TOK_SRCIP6:
			NEED1("missing source IP6");
			if (add_srcip6(cmd, *av)) {
				av++;
			}
			break;

		case TOK_DSTIP6:
			NEED1("missing destination IP6");
			if (add_dstip6(cmd, *av)) {
				av++;
			}
			break;
*/
		case TOK_SRCPORT:
			NEED1("missing source port");
			if (_substrcmp(*av, "any") == 0 ||
			    add_ports(cmd, *av, proto, O_IP_SRCPORT)) {
				av++;
			} else
				errx(EX_DATAERR, "invalid source port %s", *av);
			break;

		case TOK_DSTPORT:
			NEED1("missing destination port");
			if (_substrcmp(*av, "any") == 0 ||
			    add_ports(cmd, *av, proto, O_IP_DSTPORT)) {
				av++;
			} else
				errx(EX_DATAERR, "invalid destination port %s",
				    *av);
			break;

		case TOK_MAC:
			if (add_mac(cmd, av))
				av += 2;
			break;

		case TOK_MACTYPE:
			NEED1("missing mac type");
			if (!add_mactype(cmd, *av))
				errx(EX_DATAERR, "invalid mac type %s", *av);
			av++;
			break;

		case TOK_VERREVPATH:
			fill_cmd(cmd, O_VERREVPATH, 0, 0);
			break;

		case TOK_VERSRCREACH:
			fill_cmd(cmd, O_VERSRCREACH, 0, 0);
			break;

		case TOK_ANTISPOOF:
			fill_cmd(cmd, O_ANTISPOOF, 0, 0);
			break;

		case TOK_IPSEC:
			fill_cmd(cmd, O_IPSEC, 0, 0);
			break;

		case TOK_IPV6:
			fill_cmd(cmd, O_IP6, 0, 0);
			break;

		case TOK_IPV4:
			fill_cmd(cmd, O_IP4, 0, 0);
			break;

		/*case TOK_EXT6HDR:
			fill_ext6hdr( cmd, *av );
			av++;
			break;

		case TOK_FLOWID:
			if (proto != IPPROTO_IPV6 )
				errx( EX_USAGE, "flow-id filter is active "
				    "only for ipv6 protocol\n");
			fill_flow6( (ipfw_insn_u32 *) cmd, *av );
			av++;
			break;
*/
		case TOK_COMMENT:
			fill_comment(cmd, av);
			av[0]=NULL;
			break;

		case TOK_TAGGED:
			if (av[0] && strpbrk(*av, "-,")) {
				if (!add_ports(cmd, *av, 0, O_TAGGED))
					errx(EX_DATAERR, "tagged: invalid tag"
					    " list: %s", *av);
			}
			else {
				uint16_t tag;

				GET_UINT_ARG(tag, IPFW_ARG_MIN, IPFW_ARG_MAX,
				    TOK_TAGGED, rule_options);
				fill_cmd(cmd, O_TAGGED, 0, tag);
			}
			av++;
			break;

		case TOK_FIB:
			NEED1("fib requires fib number");
			fill_cmd(cmd, O_FIB, 0, strtoul(*av, NULL, 0));
			av++;
			break;

		case TOK_LOOKUP: {
			ipfw_insn_u32 *c = (ipfw_insn_u32 *)cmd;
			char *p;
			int j;

			if (!av[0] || !av[1])
				errx(EX_USAGE, "format: lookup argument tablenum");
			cmd->opcode = O_IP_DST_LOOKUP;
			cmd->len |= F_INSN_SIZE(ipfw_insn) + 2;
			i = match_token(rule_options, *av);
			for (j = 0; lookup_key[j] >= 0 ; j++) {
				if (i == lookup_key[j])
					break;
			}
			if (lookup_key[j] <= 0)
				errx(EX_USAGE, "format: cannot lookup on %s", *av);
			c->d[1] = j; // i converted to option
			av++;
			cmd->arg1 = strtoul(*av, &p, 0);
			if (p && *p)
				errx(EX_USAGE, "format: lookup argument tablenum");
			av++;
		    }
			break;

		default:
			errx(EX_USAGE, "unrecognised option [%d] %s\n", i, s);
		}
		if (F_LEN(cmd) > 0) {	/* prepare to advance */
			prev = cmd;
			cmd = next_cmd(cmd);
		}
	}

done:
	/*
	 * Now copy stuff into the rule.
	 * If we have a keep-state option, the first instruction
	 * must be a PROBE_STATE (which is generated here).
	 * If we have a LOG option, it was stored as the first command,
	 * and now must be moved to the top of the action part.
	 */
	dst = (ipfw_insn *)rule->cmd;

	/*
	 * First thing to write into the command stream is the match probability.
	 */
	if (match_prob != 1) { /* 1 means always match */
		dst->opcode = O_PROB;
		dst->len = 2;
		*((int32_t *)(dst+1)) = (int32_t)(match_prob * 0x7fffffff);
		dst += dst->len;
	}

	/*
	 * generate O_PROBE_STATE if necessary
	 */
	if (have_state && have_state->opcode != O_CHECK_STATE) {
		fill_cmd(dst, O_PROBE_STATE, 0, 0);
		dst = next_cmd(dst);
	}

	/* copy all commands but O_LOG, O_KEEP_STATE, O_LIMIT, O_ALTQ, O_TAG */
	for (src = (ipfw_insn *)cmdbuf; src != cmd; src += i) {
		i = F_LEN(src);

		switch (src->opcode) {
		case O_LOG:
		case O_KEEP_STATE:
		case O_LIMIT:
		case O_ALTQ:
		case O_TAG:
			break;
		default:
			bcopy(src, dst, i * sizeof(uint32_t));
			dst += i;
		}
	}

	/*
	 * put back the have_state command as last opcode
	 */
	if (have_state && have_state->opcode != O_CHECK_STATE) {
		i = F_LEN(have_state);
		bcopy(have_state, dst, i * sizeof(uint32_t));
		dst += i;
	}
	/*
	 * start action section
	 */
	rule->act_ofs = dst - rule->cmd;

	/* put back O_LOG, O_ALTQ, O_TAG if necessary */
	if (have_log) {
		i = F_LEN(have_log);
		bcopy(have_log, dst, i * sizeof(uint32_t));
		dst += i;
	}
	if (have_altq) {
		i = F_LEN(have_altq);
		bcopy(have_altq, dst, i * sizeof(uint32_t));
		dst += i;
	}
	if (have_tag) {
		i = F_LEN(have_tag);
		bcopy(have_tag, dst, i * sizeof(uint32_t));
		dst += i;
	}
	/*
	 * copy all other actions
	 */
	for (src = (ipfw_insn *)actbuf; src != action; src += i) {
		i = F_LEN(src);
		bcopy(src, dst, i * sizeof(uint32_t));
		dst += i;
	}

	rule->cmd_len = (uint32_t *)dst - (uint32_t *)(rule->cmd);


	//add rule to chain
        i = (char *)dst - (char *)rule; //calculate length

	struct ip_fw * rule_in_chain = NULL;
	struct ip_fw_chain * chain = &layer3_chain;
	chain->n_rules +=1;
	chain->static_len += i;
//	chain->map = realloc(chain->map, chain->static_len);
	if (chain->map)
		rule_in_chain = malloc(i, M_IPFW, M_NOWAIT | M_ZERO);
	if (rule_in_chain == NULL) {
		if (chain->map)
			free(chain->map, M_IPFW);
	}
        memcpy(rule_in_chain, rule, i);
	int k;
	for(k = chain->n_rules; k > 0 ; --k)
	{
	    chain->map[k] = chain->map[k-1];
	}
	chain->map[0] = rule_in_chain;
	//chain->map[(chain->n_rules) - 1] = rule_in_chain;
	rule->id = chain->n_rules - 1;

}
