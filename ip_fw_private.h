#ifndef IP_FW_PRIVATE_H_
#define IP_FW_PRIVATE_H_

#define IP_FW_PORT_DYNT_FLAG	0x10000
#define	IP_FW_PORT_TEE_FLAG	0x20000
#define	IP_FW_PORT_DENY_FLAG	0x40000

#define M_IPFW 83

//these defines originally located in sys/sys/mbuf.h of FreeBSD stack
#define	M_SKIP_FIREWALL	0x00004000 /* skip firewall processing */
#define	M_FREELIST	0x00008000 /* mbuf is on the free list */
#define	M_VLANTAG	0x00010000 /* ether_vtag is valid */
#define	M_PROMISC	0x00020000 /* packet was not for us */
#define	M_NOFREE	0x00040000 /* do not free mbuf, embedded in cluster */
#define	M_PROTO6	0x00080000 /* protocol-specific */
#define	M_PROTO7	0x00100000 /* protocol-specific */
#define	M_PROTO8	0x00200000 /* protocol-specific */
#define	M_FLOWID	0x00400000 /* flowid is valid */

/*
 * Length of interface external name, including terminating '\0'.
 * Note: this is the same size as a generic device's external name.
 */
#define		IFNAMSIZ	16
#define         IF_NAMESIZE     16

/* Return values from ipfw_chk() */

enum {
	IP_FW_PASS = 0,
	IP_FW_DENY,
	IP_FW_DIVERT,
	IP_FW_TEE,
	IP_FW_DUMMYNET,
	IP_FW_NETGRAPH,
	IP_FW_NGTEE,
	IP_FW_NAT,
	IP_FW_REASS,
};

enum {
	IPFW_INFO_MASK	= 0x0000ffff,
	IPFW_INFO_OUT	= 0x00000000,	/* outgoing, just for convenience */
	IPFW_INFO_IN	= 0x80000000,	/* incoming, overloads dir */
	IPFW_ONEPASS	= 0x40000000,	/* One-pass, do not reinject */
	IPFW_IS_MASK	= 0x30000000,	/* which source ? */
	IPFW_IS_DIVERT	= 0x20000000,
	IPFW_IS_DUMMYNET =0x10000000,
	IPFW_IS_PIPE	= 0x08000000,	/* pip1=1, queue = 0 */
};
#define MTAG_IPFW	1148380143	/* IPFW-tagged cookie */
#define MTAG_IPFW_RULE	1262273568	/* rule reference */

/*
 * The default rule number.  By the design of ip_fw, the default rule
 * is the last one, so its number can also serve as the highest number
 * allowed for a rule.  The ip_fw code relies on both meanings of this
 * constant.
 */
#define	IPFW_DEFAULT_RULE	65535

/*
 * Most commands (queue, pipe, tag, untag, limit...) can have a 16-bit
 * argument between 1 and 65534. The value 0 is unused, the value
 * 65535 (IP_FW_TABLEARG) is used to represent 'tablearg', i.e. the
 * can be 1..65534, or 65535 to indicate the use of a 'tablearg'
 * result of the most recent table() lookup.
 * Note that 16bit is only a historical limit, resulting from
 * the use of a 16-bit fields for that value. In reality, we can have
 * 2^32 pipes, queues, tag values and so on, and use 0 as a tablearg.
 */
#define	IPFW_ARG_MIN		1
#define	IPFW_ARG_MAX		65534
#define IP_FW_TABLEARG		65535	/* XXX should use 0 */

/*
 * This union structure identifies an interface, either explicitly
 * by name or implicitly by IP address. The flags IP_FW_F_IIFNAME
 * and IP_FW_F_OIFNAME say how to interpret this structure. An
 * interface unit number of -1 matches any unit number, while an
 * IP address of 0.0.0.0 indicates matches any interface.
 *
 * The receive and transmit interfaces are only compared against the
 * the packet if the corresponding bit (IP_FW_F_IIFACE or IP_FW_F_OIFACE)
 * is set. Note some packets lack a receive or transmit interface
 * (in which case the missing "interface" never matches).
 */
enum ipfw_opcodes {		/* arguments (4 byte each)	*/
	O_NOP,

	O_IP_SRC,		/* u32 = IP			*/
	O_IP_SRC_MASK,		/* ip = IP/mask			*/
	O_IP_SRC_ME,		/* none				*/
	O_IP_SRC_SET,		/* u32=base, arg1=len, bitmap	*/

	O_IP_DST,		/* u32 = IP			*/
	O_IP_DST_MASK,		/* ip = IP/mask			*/
	O_IP_DST_ME,		/* none				*/
	O_IP_DST_SET,		/* u32=base, arg1=len, bitmap	*/

	O_IP_SRCPORT,		/* (n)port list:mask 4 byte ea	*/
	O_IP_DSTPORT,		/* (n)port list:mask 4 byte ea	*/
	O_PROTO,		/* arg1=protocol		*/

	O_MACADDR2,		/* 2 mac addr:mask		*/
	O_MAC_TYPE,		/* same as srcport		*/

	O_LAYER2,		/* none				*/
	O_IN,			/* none				*/
	O_FRAG,			/* none				*/

	O_RECV,			/* none				*/
	O_XMIT,			/* none				*/
	O_VIA,			/* none				*/

	O_IPOPT,		/* arg1 = 2*u8 bitmap		*/
	O_IPLEN,		/* arg1 = len			*/
	O_IPID,			/* arg1 = id			*/

	O_IPTOS,		/* arg1 = id			*/
	O_IPPRECEDENCE,		/* arg1 = precedence << 5	*/
	O_IPTTL,		/* arg1 = TTL			*/

	O_IPVER,		/* arg1 = version		*/
	O_UID,			/* u32 = id			*/
	O_GID,			/* u32 = id			*/
	O_ESTAB,		/* none (tcp established)	*/
	O_TCPFLAGS,		/* arg1 = 2*u8 bitmap		*/
	O_TCPWIN,		/* arg1 = desired win		*/
	O_TCPSEQ,		/* u32 = desired seq.		*/
	O_TCPACK,		/* u32 = desired seq.		*/
	O_ICMPTYPE,		/* u32 = icmp bitmap		*/
	O_TCPOPTS,		/* arg1 = 2*u8 bitmap		*/

	O_VERREVPATH,		/* none				*/
	O_VERSRCREACH,		/* none				*/

	O_PROBE_STATE,		/* none				*/
	O_KEEP_STATE,		/* none				*/
	O_LIMIT,		/* ipfw_insn_limit		*/
	O_LIMIT_PARENT,		/* dyn_type, not an opcode.	*/

	/*
	 * These are really 'actions'.
	 */

	O_LOG,			/* ipfw_insn_log		*/
	O_PROB,			/* u32 = match probability	*/

	O_CHECK_STATE,		/* none				*/
	O_ACCEPT,		/* none				*/
	O_DENY,			/* none 			*/
	O_REJECT,		/* arg1=icmp arg (same as deny)	*/
	O_COUNT,		/* none				*/
	O_SKIPTO,		/* arg1=next rule number	*/
	O_PIPE,			/* arg1=pipe number		*/
	O_QUEUE,		/* arg1=queue number		*/
	O_DIVERT,		/* arg1=port number		*/
	O_TEE,			/* arg1=port number		*/
	O_FORWARD_IP,		/* fwd sockaddr			*/
	O_FORWARD_MAC,		/* fwd mac			*/
	O_NAT,                  /* nope                         */
	O_REASS,                /* none                         */

	/*
	 * More opcodes.
	 */
	O_IPSEC,		/* has ipsec history 		*/
	O_IP_SRC_LOOKUP,	/* arg1=table number, u32=value	*/
	O_IP_DST_LOOKUP,	/* arg1=table number, u32=value	*/
	O_ANTISPOOF,		/* none				*/
	O_JAIL,			/* u32 = id			*/
	O_ALTQ,			/* u32 = altq classif. qid	*/
	O_DIVERTED,		/* arg1=bitmap (1:loop, 2:out)	*/
	O_TCPDATALEN,		/* arg1 = tcp data len		*/
	O_IP6_SRC,		/* address without mask		*/
	O_IP6_SRC_ME,		/* my addresses			*/
	O_IP6_SRC_MASK,		/* address with the mask	*/
	O_IP6_DST,
	O_IP6_DST_ME,
	O_IP6_DST_MASK,
	O_FLOW6ID,		/* for flow id tag in the ipv6 pkt */
	O_ICMP6TYPE,		/* icmp6 packet type filtering	*/
	O_EXT_HDR,		/* filtering for ipv6 extension header */
	O_IP6,

	/*
	 * actions for ng_ipfw
	 */
	O_NETGRAPH,		/* send to ng_ipfw		*/
	O_NGTEE,		/* copy to ng_ipfw		*/

	O_IP4,

	O_UNREACH6,		/* arg1=icmpv6 code arg (deny)  */

	O_TAG,   		/* arg1=tag number */
	O_TAGGED,		/* arg1=tag number */

	O_SETFIB,		/* arg1=FIB number */
	O_FIB,			/* arg1=FIB desired fib number */

	O_LAST_OPCODE		/* not an opcode!		*/
};
/*
 * The extension header are filtered only for presence using a bit
 * vector with a flag for each header.
 */
#define EXT_FRAGMENT	0x1
#define EXT_HOPOPTS	0x2
#define EXT_ROUTING	0x4
#define EXT_AH		0x8
#define EXT_ESP		0x10
#define EXT_DSTOPTS	0x20
#define EXT_RTHDR0		0x40
#define EXT_RTHDR2		0x80

/*
 * Template for instructions.
 *
 * ipfw_insn is used for all instructions which require no operands,
 * a single 16-bit value (arg1), or a couple of 8-bit values.
 *
 * For other instructions which require different/larger arguments
 * we have derived structures, ipfw_insn_*.
 *
 * The size of the instruction (in 32-bit words) is in the low
 * 6 bits of "len". The 2 remaining bits are used to implement
 * NOT and OR on individual instructions. Given a type, you can
 * compute the length to be put in "len" using F_INSN_SIZE(t)
 *
 * F_NOT	negates the match result of the instruction.
 *
 * F_OR		is used to build or blocks. By default, instructions
 *		are evaluated as part of a logical AND. An "or" block
 *		{ X or Y or Z } contains F_OR set in all but the last
 *		instruction of the block. A match will cause the code
 *		to skip past the last instruction of the block.
 *
 * NOTA BENE: in a couple of places we assume that
 *	sizeof(ipfw_insn) == sizeof(u_int32_t)
 * this needs to be fixed.
 *
 */


/*
 * The F_INSN_SIZE(type) computes the size, in 4-byte words, of
 * a given type.
 */
#define	F_INSN_SIZE(t)	((sizeof (t))/sizeof(u_int32_t))

/*
 * This is used to store an array of 16-bit entries (ports etc.)
 */
typedef struct	_ipfw_insn_u16 {
	ipfw_insn o;
	u_int16_t ports[2];	/* there may be more */
} ipfw_insn_u16;

/*
 * This is used to store an array of 32-bit entries
 * (uid, single IPv4 addresses etc.)
 */
typedef struct	_ipfw_insn_u32 {
	ipfw_insn o;
	u_int32_t d[1];	/* one or more */
} ipfw_insn_u32;

/*
 * This is used to store IP addr-mask pairs.
 */
typedef struct	_ipfw_insn_ip {
	ipfw_insn o;
	struct in_addr	addr;
	struct in_addr	mask;
} ipfw_insn_ip;

/*
 * This is used for interface match rules (recv xx, xmit xx).
 */
typedef struct	_ipfw_insn_if {
	ipfw_insn o;
	union {
		struct in_addr ip;
		int glob;
	} p;
	char name[IFNAMSIZ];
} ipfw_insn_if;

/*
 * This is used for limit rules.
 */
typedef struct	_ipfw_insn_limit {
	ipfw_insn o;
	u_int8_t _pad;
	u_int8_t limit_mask;	/* combination of DYN_* below	*/
#define	DYN_SRC_ADDR	0x1
#define	DYN_SRC_PORT	0x2
#define	DYN_DST_ADDR	0x4
#define	DYN_DST_PORT	0x8

	u_int16_t conn_limit;
} ipfw_insn_limit;


/*
 * This is used for storing an altq queue id number.
 */
typedef struct _ipfw_insn_altq {
	ipfw_insn	o;
	u_int32_t	qid;
} ipfw_insn_altq;

union ip_fw_if {
    struct in_addr fu_via_ip;	/* Specified by IP address */
    struct {			/* Specified by interface name */
#define FW_IFNLEN     10 /* need room ! was IFNAMSIZ */
	    char  name[FW_IFNLEN];
	    short unit;		/* -1 means match any unit */
    } fu_via_if;
};

/*
 * This is used for MAC addr-mask pairs.
 */
typedef struct	_ipfw_insn_mac {
	ipfw_insn o;
	u_char addr[12];	/* dst[6] + src[6] */
	u_char mask[12];	/* dst[6] + src[6] */
} ipfw_insn_mac;

/*
 * This is used to forward to a given address (ip).
 */
typedef struct  _ipfw_insn_sa {
	ipfw_insn o;
	struct sockaddr_in sa;
} ipfw_insn_sa;

/*
 * This is used for log instructions.
 */
typedef struct  _ipfw_insn_log {
        ipfw_insn o;
	u_int32_t max_log;	/* how many do we log -- 0 = all */
	u_int32_t log_left;	/* how many left to log 	*/
} ipfw_insn_log;


/*
 * Dynamic ipfw rule.
 */
typedef struct _ipfw_dyn_rule ipfw_dyn_rule;

struct _ipfw_dyn_rule {
	ipfw_dyn_rule	*next;		/* linked list of rules.	*/
	struct ip_fw *rule;		/* pointer to rule		*/
	/* 'rule' is used to pass up the rule number (from the parent)	*/

	ipfw_dyn_rule *parent;		/* pointer to parent rule	*/
	u_int64_t	pcnt;		/* packet match counter		*/
	u_int64_t	bcnt;		/* byte match counter		*/
	struct ipfw_flow_id id;		/* (masked) flow id		*/
	u_int32_t	expire;		/* expire time			*/
	u_int32_t	bucket;		/* which bucket in hash table	*/
	u_int32_t	state;		/* state of this rule (typically a
					 * combination of TCP flags)
					 */
	u_int32_t	ack_fwd;	/* most recent ACKs in forward	*/
	u_int32_t	ack_rev;	/* and reverse directions (used	*/
					/* to generate keepalives)	*/
	u_int16_t	dyn_type;	/* rule type			*/
	u_int16_t	count;		/* refcount			*/
};


#define SOF_NAT         sizeof(struct cfg_nat)
#define SOF_REDIR       sizeof(struct cfg_redir)
#define SOF_SPOOL       sizeof(struct cfg_spool)

/* Nat command. */
typedef struct	_ipfw_insn_nat {
 	ipfw_insn	o;
 	struct cfg_nat *nat;
} ipfw_insn_nat;


#define	TCP(p)		((struct tcphdr *)(p))
#define	UDP(p)		((struct udphdr *)(p))
/*
 * ECN (Explicit Congestion Notification) codepoints in RFC3168 mapped to the
 * lower 2 bits of the TOS field.
 */
#define	IPTOS_ECN_NOTECT	0x00	/* not-ECT */
#define	IPTOS_ECN_ECT1		0x01	/* ECN-capable transport (1) */
#define	IPTOS_ECN_ECT0		0x02	/* ECN-capable transport (0) */
#define	IPTOS_ECN_CE		0x03	/* congestion experienced */
#define	IPTOS_ECN_MASK		0x03	/* ECN field mask */
#define	ICMP_REJECT_RST		0x100	/* fake ICMP code (send a TCP RST) */
#define	ICMP6_UNREACH_RST	0x100	/* fake ICMPv6 code (send a TCP RST) */
int
ipfw_chk(struct ip **, int, struct ifnet *, u_int16_t *,
	     struct mbuf **, struct ip_fw_chain **, struct sockaddr_in **);

typedef struct	_ipfw_table_entry {
	in_addr_t	addr;		/* network address		*/
	u_int32_t	value;		/* value			*/
	u_int16_t	tbl;		/* table number			*/
	u_int8_t	masklen;	/* mask length			*/
} ipfw_table_entry;

typedef struct	_ipfw_table {
	u_int32_t	size;		/* size of entries in bytes	*/
	u_int32_t	cnt;		/* # of entries			*/
	u_int16_t	tbl;		/* table number			*/
	ipfw_table_entry ent[0];	/* entries			*/
} ipfw_table;

/* In ip_fw_table.c */
struct radix_node;
int ipfw_lookup_table(struct ip_fw_chain *ch, uint16_t tbl, in_addr_t addr,
    uint32_t *val);
int ipfw_init_tables(struct ip_fw_chain *ch);
void ipfw_destroy_tables(struct ip_fw_chain *ch);
int ipfw_flush_table(struct ip_fw_chain *ch, uint16_t tbl);
int ipfw_add_table_entry(struct ip_fw_chain *ch, uint16_t tbl, in_addr_t addr,
    uint8_t mlen, uint32_t value);
int ipfw_dump_table_entry(struct radix_node *rn, void *arg);
int ipfw_del_table_entry(struct ip_fw_chain *ch, uint16_t tbl, in_addr_t addr,
    uint8_t mlen);
int ipfw_count_table(struct ip_fw_chain *ch, uint32_t tbl, uint32_t *cnt);
int ipfw_dump_table(struct ip_fw_chain *ch, ipfw_table *tbl);

int vnet_ipfw_init();

/* In ip_fw_nat.c -- XXX to be moved to ip_var.h */
#define NAT_BUF_LEN     1024
struct cfg_nat {
	/* chain of nat instances */
	LIST_ENTRY(cfg_nat)     _next;
	int                     id;                     /* nat id */
	struct in_addr          ip;                     /* nat ip address */
	char                    if_name[IF_NAMESIZE];   /* interface name */
	int                     mode;                   /* aliasing mode */
	struct libalias	        *lib;                   /* libalias instance */
	/* number of entry in spool chain */
	int                     redir_cnt;
	/* chain of redir instances */
	LIST_HEAD(redir_chain, cfg_redir) redir_chain;
};
struct cfg_redir {
	LIST_ENTRY(cfg_redir)   _next;          /* chain of redir instances */
	u_int16_t               mode;           /* type of redirect mode */
	struct in_addr	        laddr;          /* local ip address */
	struct in_addr	        paddr;          /* public ip address */
	struct in_addr	        raddr;          /* remote ip address */
	u_short                 lport;          /* local port */
	u_short                 pport;          /* public port */
	u_short                 rport;          /* remote port  */
	u_short                 pport_cnt;      /* number of public ports */
	u_short                 rport_cnt;      /* number of remote ports */
	int                     proto;          /* protocol: tcp/udp */
	struct alias_link       **alink;
	/* num of entry in spool chain */
	u_int16_t               spool_cnt;
	/* chain of spool instances */
	LIST_HEAD(spool_chain, cfg_spool) spool_chain;
};

extern struct cfg_nat *(*lookup_nat_ptr)(struct nat_list *, int);

typedef int ipfw_nat_t(struct ifnet * oif_arg, struct cfg_nat *, struct mbuf *);
typedef int ipfw_nat_cfg_t(struct sockopt *);

extern ipfw_nat_t *ipfw_nat_ptr;
#define IPFW_NAT_LOADED (ipfw_nat_ptr != NULL)

extern ipfw_nat_cfg_t *ipfw_nat_cfg_ptr;
extern ipfw_nat_cfg_t *ipfw_nat_del_ptr;
extern ipfw_nat_cfg_t *ipfw_nat_get_cfg_ptr;
extern ipfw_nat_cfg_t *ipfw_nat_get_log_ptr;
/* Server pool support (LSNAT). */
struct cfg_spool {
	LIST_ENTRY(cfg_spool)   _next;          /* chain of spool instances */
	struct in_addr          addr;
	u_short                 port;
};

/* Redirect modes id. */
#define REDIR_ADDR      0x01
#define REDIR_PORT      0x02
#define REDIR_PROTO     0x04

#endif //IP_FW_PRIVATE_H_