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

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/socketvar.h>
#include <netinet/ip_fw.h>
#include "ip_fw_private.h"

#define  time_uptime cyg_current_time(); //megahack.

struct ip_fw_chain layer3_chain;
static int default_to_accept = 0;
int V_autoinc_step = 0;

#define	M_FIB		0xF0000000 /* steal some bits to store fib number. */
#define M_FIBSHIFT    28
#define M_SETFIB(_m, _fib) do {						\
	_m->m_flags &= ~M_FIB;					   	\
	_m->m_flags |= (((_fib) << M_FIBSHIFT) & M_FIB);  \
} while (0)

/*
 * Historically, BSD keeps ip_len and ip_off in host format
 * when doing layer 3 processing, and this often requires
 * to translate the format back and forth.
 * To make the process explicit, we define a couple of macros
 * that also take into account the fact that at some point
 * we may want to keep those fields always in net format.
 */

#if (BYTE_ORDER == BIG_ENDIAN) || defined(HAVE_NET_IPLEN)
#define SET_NET_IPLEN(p)	do {} while (0)
#define SET_HOST_IPLEN(p)	do {} while (0)
#else
#define SET_NET_IPLEN(p)	do {		\
	struct ip *h_ip = (p);			\
	h_ip->ip_len = htons(h_ip->ip_len);	\
	h_ip->ip_off = htons(h_ip->ip_off);	\
	} while (0)

#define SET_HOST_IPLEN(p)	do {		\
	struct ip *h_ip = (p);			\
	h_ip->ip_len = ntohs(h_ip->ip_len);	\
	h_ip->ip_off = ntohs(h_ip->ip_off);	\
	} while (0)
#endif

struct icmphdr {
    u_char  icmp_type;              /* type of message, see below */
    u_char  icmp_code;              /* type sub code */
    u_short icmp_cksum;             /* ones complement cksum of struct */
};
/*
 * Some macros used in the various matching options.
 * L3HDR maps an ipv4 pointer into a layer3 header pointer of type T
 * Other macros just cast void * into the appropriate type
 */
#define	L3HDR(T, ip)	((T *)((u_int32_t *)(ip) + (ip)->ip_hl))
#define	TCP(p)		((struct tcphdr *)(p))
#define	SCTP(p)		((struct sctphdr *)(p))
#define	UDP(p)		((struct udphdr *)(p))
#define	ICMP(p)		((struct icmphdr *)(p))
#define	ICMP6(p)	((struct icmp6_hdr *)(p))

static __inline int
icmptype_match(struct icmphdr *icmp, ipfw_insn_u32 *cmd)
{
	int type = icmp->icmp_type;

	return (type <= ICMP_MAXTYPE && (cmd->d[0] & (1<<type)) );
}

#define TT	( (1 << ICMP_ECHO) | (1 << ICMP_ROUTERSOLICIT) | \
    (1 << ICMP_TSTAMP) | (1 << ICMP_IREQ) | (1 << ICMP_MASKREQ) )

static int
is_icmp_query(struct icmphdr *icmp)
{
	int type = icmp->icmp_type;

	return (type <= ICMP_MAXTYPE && (TT & (1<<type)) );
}
#undef TT

extern struct sockaddr_in ip_fwd;
/*
 * The following checks use two arrays of 8 or 16 bits to store the
 * bits that we want set or clear, respectively. They are in the
 * low and high half of cmd->arg1 or cmd->d[0].
 *
 * We scan options and store the bits we find set. We succeed if
 *
 *	(want_set & ~bits) == 0 && (want_clear & ~bits) == want_clear
 *
 * The code is sometimes optimized not to store additional variables.
 */

static int
flags_match(ipfw_insn *cmd, u_int8_t bits)
{
	u_char want_clear;
	bits = ~bits;

	if ( ((cmd->arg1 & 0xff) & bits) != 0)
		return 0; /* some bits we want set were clear */
	want_clear = (cmd->arg1 >> 8) & 0xff;
	if ( (want_clear & bits) != want_clear)
		return 0; /* some bits we want clear were set */
	return 1;
}

static int
ipopts_match(struct ip *ip, ipfw_insn *cmd)
{
	int optlen, bits = 0;
	u_char *cp = (u_char *)(ip + 1);
	int x = (ip->ip_hl << 2) - sizeof (struct ip);

	for (; x > 0; x -= optlen, cp += optlen) {
		int opt = cp[IPOPT_OPTVAL];

		if (opt == IPOPT_EOL)
			break;
		if (opt == IPOPT_NOP)
			optlen = 1;
		else {
			optlen = cp[IPOPT_OLEN];
			if (optlen <= 0 || optlen > x)
				return 0; /* invalid or truncated */
		}
		switch (opt) {

		default:
			break;

		case IPOPT_LSRR:
			bits |= IP_FW_IPOPT_LSRR;
			break;

		case IPOPT_SSRR:
			bits |= IP_FW_IPOPT_SSRR;
			break;

		case IPOPT_RR:
			bits |= IP_FW_IPOPT_RR;
			break;

		case IPOPT_TS:
			bits |= IP_FW_IPOPT_TS;
			break;
		}
	}
	return (flags_match(cmd, bits));
}

static int
tcpopts_match(struct tcphdr *tcp, ipfw_insn *cmd)
{
	int optlen, bits = 0;
	u_char *cp = (u_char *)(tcp + 1);
	int x = (tcp->th_off << 2) - sizeof(struct tcphdr);

	for (; x > 0; x -= optlen, cp += optlen) {
		int opt = cp[0];
		if (opt == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;
		else {
			optlen = cp[1];
			if (optlen <= 0)
				break;
		}

		switch (opt) {

		default:
			break;

		case TCPOPT_MAXSEG:
			bits |= IP_FW_TCPOPT_MSS;
			break;

		case TCPOPT_WINDOW:
			bits |= IP_FW_TCPOPT_WINDOW;
			break;

		case TCPOPT_SACK_PERMITTED:
		case TCPOPT_SACK:
			bits |= IP_FW_TCPOPT_SACK;
			break;

		case TCPOPT_TIMESTAMP:
			bits |= IP_FW_TCPOPT_TS;
			break;

		}
	}
	return (flags_match(cmd, bits));
}

static int
iface_match(struct ifnet *ifp, ipfw_insn_if *cmd)
{
	if (ifp == NULL)	/* no iface with this packet, match fails */
		return 0;
	/* Check by name or by IP address */
	if (cmd->name[0] != '\0') { /* match by name */
		/* Check name */
		if (cmd->p.glob) {
			if (fnmatch(cmd->name, ifp->if_xname, 0) == 0)
				return(1);
		} else {
			if (strncmp(ifp->if_xname, cmd->name, IFNAMSIZ) == 0)
				return(1);
		}
	} else {
#ifdef	__FreeBSD__	/* and OSX too ? */
		struct ifaddr *ia;

		//if_addr_rlock(ifp);
		TAILQ_FOREACH(ia, &ifp->if_addrhead, ifa_link) {
			if (ia->ifa_addr->sa_family != AF_INET)
				continue;
			if (cmd->p.ip.s_addr == ((struct sockaddr_in *)
			    (ia->ifa_addr))->sin_addr.s_addr) {
				//if_addr_runlock(ifp);
				return(1);	/* match */
			}
		}
		//if_addr_runlock(ifp);
#endif /* __FreeBSD__ */
	}
	return(0);	/* no match, fail ... */
}
/*
 * Helper function to set args with info on the rule after the matching
 * one. slot is precise, whereas we guess rule_id as they are
 * assigned sequentially.
 */
static inline void
set_match(struct ipfw_rule_ref *rule, int slot,
	struct ip_fw_chain *chain)
{
	rule->chain_id = chain->id;
	rule->slot = slot + 1; /* we use 0 as a marker */
	rule->rule_id = 1 + chain->map[slot]->id;
	rule->rulenum = chain->map[slot]->rulenum;
}
/*
 * Return value:
 *
 *	IP_FW_PASS	the packet must be accepted
 *	IP_FW_DENY	the packet must be dropped
 *	IP_FW_DIVERT	divert packet, port in m_tag
 *	IP_FW_TEE	tee packet, port in m_tag
 *	IP_FW_DUMMYNET	to dummynet, pipe in args->cookie
 *	IP_FW_NETGRAPH	into netgraph, cookie args->cookie
 *		args->rule contains the matching rule,
 *		args->rule.info has additional information.
 */
int
ipfw_chk(struct ip ** ip_arg,
	 int hlen_arg,
         struct ifnet * oif_arg,	//output interface
         u_int16_t * divert_cookie_arg,	
         struct mbuf ** m_arg,
         struct ip_fw_chain ** chain_arg,
         struct sockaddr_in ** ip_fw_fwd_addr)
{
//------------------------------------define local variables------------------------------------//
	
	/* m | m_arg	Pointer to the mbuf, as received from the caller.
	 *	It may change if ipfw_chk() does an m_pullup, or if it
	 *	consumes the packet because it calls send_reject().
	 *	XXX This has to change, so that ipfw_chk() never modifies
	 *	or consumes the buffer.
	 * ip	is the beginning of the ip(4 or 6) header.
	 *	Calculated by adding the L3offset to the start of data.
	 *	(Until we start using L3offset, the packet is
	 *	supposed to start with the ip header).
	 */	
	struct mbuf * m = *m_arg;
        struct ip * ip = mtod(m, struct ip *);
        
	 /*
	 * oif | args->oif	If NULL, ipfw_chk has been called on the
	 *	inbound path (ether_input, ip_input).
	 *	If non-NULL, ipfw_chk has been called on the outbound path
	 *	(ether_output, ip_output).
	 */
	struct ifnet *oif = oif_arg;

	int f_pos = 0;		/* index of current rule in the array */
	int retval = 0;

	/*
	 * hlen	The length of the IP header.
	 */
	u_int hlen = 0;		/* hlen >0 means we have an IP pkt */

	/*
	 * offset	The offset of a fragment. offset != 0 means that
	 *	we have a fragment at this offset of an IPv4 packet.
	 *	offset == 0 means that (if this is an IPv4 packet)
	 *	this is the first or only fragment.
	 *	For IPv6 offset == 0 means there is no Fragment Header.
	 *	If offset != 0 for IPv6 always use correct mask to
	 *	get the correct offset because we add IP6F_MORE_FRAG
	 *	to be able to dectect the first fragment which would
	 *	otherwise have offset = 0.
	 */
	u_short offset = 0;

	/*
	 * Local copies of addresses. They are only valid if we have
	 * an IP packet.
	 *
	 * proto	The protocol. Set to 0 for non-ip packets,
	 *	or to the protocol read from the packet otherwise.
	 *	proto != 0 means that we have an IPv4 packet.
	 *
	 * src_port, dst_port	port numbers, in HOST format. Only
	 *	valid for TCP and UDP packets.
	 *
	 * src_ip, dst_ip	ip addresses, in NETWORK format.
	 *	Only valid for IPv4 packets.
	 */
	uint8_t proto;
	uint16_t src_port = 0, dst_port = 0;	/* NOTE: host format	*/
	struct in_addr src_ip, dst_ip;		/* NOTE: network format	*/
	uint16_t iplen=0;
	int pktlen;
	uint16_t	etype = 0;	/* Host order stored ether type */


	/*
	 * dyn_dir = MATCH_UNKNOWN when rules unchecked,
	 * 	MATCH_NONE when checked and not matched (q = NULL),
	 *	MATCH_FORWARD or MATCH_REVERSE otherwise (q != NULL)
	 */
	#define MATCH_REVERSE	0
	#define MATCH_FORWARD	1
	#define MATCH_NONE	2
	#define MATCH_UNKNOWN	3

	int dyn_dir = MATCH_UNKNOWN;
	ipfw_dyn_rule *q = NULL;
	struct ip_fw_chain *chain = &layer3_chain;

	/*
	 * We store in ulp a pointer to the upper layer protocol header.
	 * In the ipv4 case this is easy to determine from the header,
	 * but for ipv6 we might have some additional headers in the middle.
	 * ulp is NULL if not found.
	 */
	void *ulp = NULL;		/* upper layer protocol pointer. */

	int is_ipv4 = 0;

	int done = 0;		/* flag to exit the outer loop */

	if (m->m_flags & M_SKIP_FIREWALL)
		return (IP_FW_PASS);	/* accept */

	dst_ip.s_addr = 0;		/* make sure it is initialized */
	src_ip.s_addr = 0;		/* make sure it is initialized */
	pktlen = m->m_pkthdr.len;
	proto = 0;	/* mark f_id invalid */
		/* XXX 0 is a valid proto: IP/IPv6 Hop-by-Hop Option */

/*
 * PULLUP_TO(len, p, T) makes sure that len + sizeof(T) is contiguous,
 * then it sets p to point at the offset "len" in the mbuf. WARNING: the
 * pointer might become stale after other pullups (but we never use it
 * this way).
 */
#define PULLUP_TO(_len, p, T)					\
do {								\
	int x = (_len) + sizeof(T);				\
	if ((m)->m_len < x) {					\
		m = m_pullup(m, x);			\
		if (m == NULL)					\
			goto pullup_failed;			\
	}							\
	p = (mtod(m, char *) + (_len));				\
} while (0)


//------------------------------------end of define local variables------------------------------------//



//---------------------------Identify IP packets and fill up variables (no IPv6)---------------------------//
	if (pktlen >= sizeof(struct ip) && ip->ip_v == 4) {
	    	is_ipv4 = 1;
		hlen = ip->ip_hl << 2;

		/*
		 * Collect parameters into local variables for faster matching.
		 */
		proto = ip->ip_p;
		src_ip = ip->ip_src;
		dst_ip = ip->ip_dst;
		offset = ntohs(ip->ip_off) & IP_OFFMASK;
		iplen = ntohs(ip->ip_len);
		pktlen = iplen < pktlen ? iplen : pktlen;

		if (offset == 0) {
			switch (proto) {
			case IPPROTO_TCP:
				PULLUP_TO(hlen, ulp, struct tcphdr);
				dst_port = TCP(ulp)->th_dport;
				src_port = TCP(ulp)->th_sport;
				break;

			case IPPROTO_UDP:
				PULLUP_TO(hlen, ulp, struct udphdr);
				dst_port = UDP(ulp)->uh_dport;
				src_port = UDP(ulp)->uh_sport;
				break;

			case IPPROTO_ICMP:
				PULLUP_TO(hlen, ulp, struct icmphdr);
				//args->f_id.flags = ICMP(ulp)->icmp_type;
				break;

			default:
				break;
			}
		}

		ip = mtod(m, struct ip *);
	}
#undef PULLUP_TO

	pthread_mutex_t mutex;
	pthread_mutex_init(&mutex, NULL);

	if (rule.slot) {
		/*
		 * Packet has already been tagged as a result of a previous
		 * match on rule args->rule aka args->rule_id (PIPE, QUEUE,
		 * REASS, NETGRAPH, DIVERT/TEE...)
		 * Validate the slot and continue from the next one
		 * if still present, otherwise do a lookup.
		 */
		f_pos = (rule.chain_id == chain->id) ?
		    rule.slot :
		    ipfw_find_rule(chain, rule.rulenum,
			rule.rule_id);
		rule.slot = 0;
	} else {
		f_pos = 0;
	}

		/*
	 * Now scan the rules, and parse microinstructions for each rule.
	 * We have two nested loops and an inner switch. Sometimes we
	 * need to break out of one or both loops, or re-enter one of
	 * the loops with updated variables. Loop variables are:
	 *
	 *	f_pos (outer loop) points to the current rule.
	 *		On output it points to the matching rule.
	 *	done (outer loop) is used as a flag to break the loop.
	 *	l (inner loop)	residual length of current rule.
	 *		cmd points to the current microinstruction.
	 *
	 * We break the inner loop by setting l=0 and possibly
	 * cmdlen=0 if we don't want to advance cmd.
	 * We break the outer loop by setting done=1
	 * We can restart the inner loop by setting l>0 and f_pos, f, cmd
	 * as needed.
	 */
	for (; f_pos < chain->n_rules; f_pos++) {
		ipfw_insn *cmd;
		uint32_t tablearg = 0;
		int l, cmdlen, skip_or; /* skip rest of OR block */
		struct ip_fw *f;

		f = chain->map[f_pos];

		skip_or = 0;
		for (l = f->cmd_len, cmd = f->cmd ; l > 0 ;
		    l -= cmdlen, cmd += cmdlen) {
			int match;

			/*
			 * check_body is a jump target used when we find a
			 * CHECK_STATE, and need to jump to the body of
			 * the target rule.
			 */

/* check_body: */
			cmdlen = F_LEN(cmd);
			/*
			 * An OR block (insn_1 || .. || insn_n) has the
			 * F_OR bit set in all but the last instruction.
			 * The first match will set "skip_or", and cause
			 * the following instructions to be skipped until
			 * past the one with the F_OR bit clear.
			 */
			if (skip_or) {		/* skip this instruction */
				if ((cmd->len & F_OR) == 0)
					skip_or = 0;	/* next one is good */
				continue;
			}
			match = 0; /* set to 1 if we succeed */

			switch (cmd->opcode) {
			/*
			 * The first set of opcodes compares the packet's
			 * fields with some pattern, setting 'match' if a
			 * match is found. At the end of the loop there is
			 * logic to deal with F_NOT and F_OR flags associated
			 * with the opcode.
			 */
			case O_NOP:
				match = 1;
				break;

			case O_FORWARD_MAC:
				printf("ipfw: opcode %d unimplemented\n",
				    cmd->opcode);
				break;

			case O_GID:
			case O_UID:
			case O_JAIL:
				/*
				 * We only check offset == 0 && proto != 0,
				 * as this ensures that we have a
				 * packet with the ports info.
				 */
				if (offset!=0)
				break;				
				/*if (proto == IPPROTO_TCP ||
				    proto == IPPROTO_UDP)
					match = check_uidgid(
						    (ipfw_insn_u32 *)cmd,
						    proto, oif,
						    dst_ip, dst_port,
						    src_ip, src_port, &ucred_lookup,
#ifdef __FreeBSD__
						    &ucred_cache, args->inp);
#else
						    (void *)&ucred_cache,
						    (struct inpcb *)args->m);
#endif*/
				break;

			case O_RECV:
				match = iface_match(m->m_pkthdr.rcvif,
				    (ipfw_insn_if *)cmd);
				break;

			case O_XMIT:
				match = iface_match(oif, (ipfw_insn_if *)cmd);
				break;

			case O_VIA:
				match = iface_match(oif ? oif :
				    m->m_pkthdr.rcvif, (ipfw_insn_if *)cmd);
				break;

			case O_MACADDR2:
				break;

			case O_MAC_TYPE:				
				break;

			case O_FRAG:
				match = (offset != 0);
				break;

			case O_IN:	/* "out" is "not in" */
				match = (oif == NULL);
				break;

			case O_LAYER2:				
				break;

			case O_DIVERTED:
			    {
				/* For diverted packets, args->rule.info
				 * contains the divert port (in host format)
				 * reason and direction.
	 			 */
				/*uint32_t i = rule.info;
				match = (i&IPFW_IS_MASK) == IPFW_IS_DIVERT &&
				    cmd->arg1 & ((i & IPFW_INFO_IN) ? 1 : 2);*/
			    }
				break;

			case O_PROTO:
				/*
				 * We do not allow an arg of 0 so the
				 * check of "proto" only suffices.
				 */
				match = (proto == cmd->arg1);
				break;

			case O_IP_SRC:
				match = is_ipv4 &&
				    (((ipfw_insn_ip *)cmd)->addr.s_addr ==
				    src_ip.s_addr);
				break;

			case O_IP_SRC_LOOKUP:
			case O_IP_DST_LOOKUP:
				if (is_ipv4) {
				    uint32_t key =
					(cmd->opcode == O_IP_DST_LOOKUP) ?
					    dst_ip.s_addr : src_ip.s_addr;
				    uint32_t v = 0;

				    if (cmdlen > F_INSN_SIZE(ipfw_insn_u32)) {
					/* generic lookup. The key must be
					 * in 32bit big-endian format.
					 */
					v = ((ipfw_insn_u32 *)cmd)->d[1];
					if (v == 0)
					    key = dst_ip.s_addr;
					else if (v == 1)
					    key = src_ip.s_addr;
					else if (v == 6) /* dscp */
					    key = (ip->ip_tos >> 2) & 0x3f;
					else if (offset != 0)
					    break;
					else if (proto != IPPROTO_TCP &&
						proto != IPPROTO_UDP)
					    break;
					else if (v == 2)
					    key = htonl(dst_port);
					else if (v == 3)
					    key = htonl(src_port);
					else if (v == 4 || v == 5) {
					//some staff was here, with UID & GID check
					} else
					    break;
				    }
				    match = ipfw_lookup_table(chain,
					cmd->arg1, key, &v);
				    if (!match)
					break;
				    if (cmdlen == F_INSN_SIZE(ipfw_insn_u32))
					match =
					    ((ipfw_insn_u32 *)cmd)->d[0] == v;
				    else
					tablearg = v;
				}
				break;

			case O_IP_SRC_MASK:
			case O_IP_DST_MASK:
				if (is_ipv4) {
				    uint32_t a =
					(cmd->opcode == O_IP_DST_MASK) ?
					    dst_ip.s_addr : src_ip.s_addr;
				    uint32_t *p = ((ipfw_insn_u32 *)cmd)->d;
				    int i = cmdlen-1;

				    for (; !match && i>0; i-= 2, p+= 2)
					match = (p[0] == (a & p[1]));
				}
				break;

			case O_IP_SRC_ME:
				if (is_ipv4) {
					struct ifnet *tif;

					INADDR_TO_IFP(src_ip, tif);
					match = (tif != NULL);
					break;
				}
#ifdef INET6
				/* FALLTHROUGH */
			case O_IP6_SRC_ME:
				match= is_ipv6 && search_ip6_addr_net(&args->f_id.src_ip6);
#endif
				break;

			case O_IP_DST_SET:
			case O_IP_SRC_SET:
				/*if (is_ipv4) {
					u_int32_t *d = (u_int32_t *)(cmd+1);
					u_int32_t addr =
					    cmd->opcode == O_IP_DST_SET ?
						args->f_id.dst_ip :
						args->f_id.src_ip;

					    if (addr < d[0])
						    break;
					    addr -= d[0]; subtract base
					    match = (addr < cmd->arg1) &&
						( d[ 1 + (addr>>5)] &
						  (1<<(addr & 0x1f)) );
				}*/
				break;

			case O_IP_DST:
				match = is_ipv4 &&
				    (((ipfw_insn_ip *)cmd)->addr.s_addr ==
				    dst_ip.s_addr);
				break;

			case O_IP_DST_ME:
				if (is_ipv4) {
					struct ifnet *tif;

					INADDR_TO_IFP(dst_ip, tif);
					match = (tif != NULL);
					break;
				}
#ifdef INET6
				/* FALLTHROUGH */
			case O_IP6_DST_ME:
				//match= is_ipv6 && search_ip6_addr_net(&args->f_id.dst_ip6);
#endif
				break;


			case O_IP_SRCPORT:
			case O_IP_DSTPORT:
				/*
				 * offset == 0 && proto != 0 is enough
				 * to guarantee that we have a
				 * packet with port info.
				 */
				if ((proto==IPPROTO_UDP || proto==IPPROTO_TCP)
				    && offset == 0) {
					u_int16_t x =
					    (cmd->opcode == O_IP_SRCPORT) ?
						src_port : dst_port ;
					u_int16_t *p =
					    ((ipfw_insn_u16 *)cmd)->ports;
					int i;

					for (i = cmdlen - 1; !match && i>0;
					    i--, p += 2)
						match = (x>=p[0] && x<=p[1]);
				}
				break;

			case O_ICMPTYPE:
				match = (offset == 0 && proto==IPPROTO_ICMP &&
				    icmptype_match(ICMP(ulp), (ipfw_insn_u32 *)cmd) );
				break;

#ifdef INET6
			case O_ICMP6TYPE:
				match = is_ipv6 && offset == 0 &&
				    proto==IPPROTO_ICMPV6 &&
				    icmp6type_match(
					ICMP6(ulp)->icmp6_type,
					(ipfw_insn_u32 *)cmd);
				break;
#endif /* INET6 */

			case O_IPOPT:
				match = (is_ipv4 &&
				    ipopts_match(ip, cmd) );
				break;

			case O_IPVER:
				match = (is_ipv4 &&
				    cmd->arg1 == ip->ip_v);
				break;

			case O_IPID:
			case O_IPLEN:
			case O_IPTTL:
				if (is_ipv4) {	/* only for IP packets */
				    uint16_t x;
				    uint16_t *p;
				    int i;

				    if (cmd->opcode == O_IPLEN)
					x = iplen;
				    else if (cmd->opcode == O_IPTTL)
					x = ip->ip_ttl;
				    else /* must be IPID */
					x = ntohs(ip->ip_id);
				    if (cmdlen == 1) {
					match = (cmd->arg1 == x);
					break;
				    }
				    /* otherwise we have ranges */
				    p = ((ipfw_insn_u16 *)cmd)->ports;
				    i = cmdlen - 1;
				    for (; !match && i>0; i--, p += 2)
					match = (x >= p[0] && x <= p[1]);
				}
				break;

			case O_IPPRECEDENCE:
				match = (is_ipv4 &&
				    (cmd->arg1 == (ip->ip_tos & 0xe0)) );
				break;

			case O_IPTOS:
				match = (is_ipv4 &&
				    flags_match(cmd, ip->ip_tos));
				break;

			case O_TCPDATALEN:
				if (proto == IPPROTO_TCP && offset == 0) {
				    struct tcphdr *tcp;
				    uint16_t x;
				    uint16_t *p;
				    int i;

				    tcp = TCP(ulp);
				    x = iplen -
					((ip->ip_hl + tcp->th_off) << 2);
				    if (cmdlen == 1) {
					match = (cmd->arg1 == x);
					break;
				    }
				    /* otherwise we have ranges */
				    p = ((ipfw_insn_u16 *)cmd)->ports;
				    i = cmdlen - 1;
				    for (; !match && i>0; i--, p += 2)
					match = (x >= p[0] && x <= p[1]);
				}
				break;

			case O_TCPFLAGS:
				match = (proto == IPPROTO_TCP && offset == 0 &&
				    flags_match(cmd, TCP(ulp)->th_flags));
				break;

			case O_TCPOPTS:
				match = (proto == IPPROTO_TCP && offset == 0 &&
				    tcpopts_match(TCP(ulp), cmd));
				break;

			case O_TCPSEQ:
				match = (proto == IPPROTO_TCP && offset == 0 &&
				    ((ipfw_insn_u32 *)cmd)->d[0] ==
					TCP(ulp)->th_seq);
				break;

			case O_TCPACK:
				match = (proto == IPPROTO_TCP && offset == 0 &&
				    ((ipfw_insn_u32 *)cmd)->d[0] ==
					TCP(ulp)->th_ack);
				break;

			case O_TCPWIN:
				match = (proto == IPPROTO_TCP && offset == 0 &&
				    cmd->arg1 == TCP(ulp)->th_win);
				break;

			case O_ESTAB:
				/* reject packets which have SYN only */
				/* XXX should i also check for TH_ACK ? */
				match = (proto == IPPROTO_TCP && offset == 0 &&
				    (TCP(ulp)->th_flags &
				     (TH_RST | TH_ACK | TH_SYN)) != TH_SYN);
				break;

			case O_ALTQ: {
				/*struct pf_mtag *at;
				ipfw_insn_altq *altq = (ipfw_insn_altq *)cmd;

				match = 1;
				at = pf_find_mtag(m);
				if (at != NULL && at->qid != 0)
					break;
				at = pf_get_mtag(m);
				if (at == NULL) {*/
					/*
					 * Let the packet fall back to the
					 * default ALTQ.
					 */
				/*	break;
				}
				at->qid = altq->qid;
				if (is_ipv4)
					at->af = AF_INET;
				else
					at->af = AF_LINK;
				at->hdr = ip;*/
				break;
			}

			case O_LOG:
				/*ipfw_log(f, hlen, args, m,
					    oif, offset, tablearg, ip);*/
				match = 1;
				break;

			case O_PROB:
				match = (random()<((ipfw_insn_u32 *)cmd)->d[0]);
				break;

			case O_VERREVPATH:
				/* Outgoing packets automatically pass/match */
				/*match = ((oif != NULL) ||
				    (m->m_pkthdr.rcvif == NULL) ||
				    (
#ifdef INET6
				    is_ipv6 ?
					verify_path6(&(args->f_id.src_ip6),
					    m->m_pkthdr.rcvif) :
#endif
				    /*verify_path(src_ip, m->m_pkthdr.rcvif,
				        args->f_id.fib)));*/
				break;

			case O_VERSRCREACH:
				/* Outgoing packets automatically pass/match */
				//match = (hlen > 0 && ((oif != NULL) ||
#ifdef INET6
				    is_ipv6 ?
				        verify_path6(&(args->f_id.src_ip6),
				            NULL) :
#endif
				   // verify_path(src_ip, NULL, args->f_id.fib)));
				break;

			case O_ANTISPOOF:
				/* Outgoing packets automatically pass/match */
				/*if (oif == NULL && hlen > 0 &&
				    (  (is_ipv4 && in_localaddr(src_ip))
#ifdef INET6
				    || (is_ipv6 &&
				        in6_localaddr(&(args->f_id.src_ip6)))
#endif
				    ))
					match =
#ifdef INET6
					    is_ipv6 ? verify_path6(
					        &(args->f_id.src_ip6),
					        m->m_pkthdr.rcvif) :
#endif
					    verify_path(src_ip,
					    	m->m_pkthdr.rcvif,
					        args->f_id.fib);
				else
					match = 1;*/
				break;

			case O_IPSEC:
#ifdef IPSEC
				match = (m_tag_find(m,
				    PACKET_TAG_IPSEC_IN_DONE, NULL) != NULL);
#endif
				/* otherwise no match */
				break;

			case O_IP4:
				match = is_ipv4;
				break;

			case O_TAG: {
			/*	struct m_tag *mtag;
				uint32_t tag = (cmd->arg1 == IP_FW_TABLEARG) ?
				    tablearg : cmd->arg1;
			*/
				/* Packet is already tagged with this tag? */
			//	mtag = m_tag_locate(m, MTAG_IPFW, tag, NULL);

				/* We have `untag' action when F_NOT flag is
				 * present. And we must remove this mtag from
				 * mbuf and reset `match' to zero (`match' will
				 * be inversed later).
				 * Otherwise we should allocate new mtag and
				 * push it into mbuf.
				 */
			//	if (cmd->len & F_NOT) { /* `untag' action */
			/*		if (mtag != NULL)
						m_tag_delete(m, mtag);
					match = 0;
				} else if (mtag == NULL) {
					if ((mtag = m_tag_alloc(MTAG_IPFW,
					    tag, 0, M_NOWAIT)) != NULL)
						m_tag_prepend(m, mtag);
					match = 1;
				}*/
				break;
			}

			case O_FIB: /* try match the specified fib */
				/*if (args->f_id.fib == cmd->arg1)
					match = 1;*/
				break;

			case O_TAGGED: {
				/*struct m_tag *mtag;
				uint32_t tag = (cmd->arg1 == IP_FW_TABLEARG) ?
				    tablearg : cmd->arg1;

				if (cmdlen == 1) {
					match = m_tag_locate(m, MTAG_IPFW,
					    tag, NULL) != NULL;
					break;
				}*/

				/* we have ranges */
				/*for (mtag = m_tag_first(m);
				    mtag != NULL && !match;
				    mtag = m_tag_next(m, mtag)) {
					uint16_t *p;
					int i;

					if (mtag->m_tag_cookie != MTAG_IPFW)
						continue;

					p = ((ipfw_insn_u16 *)cmd)->ports;
					i = cmdlen - 1;
					for(; !match && i > 0; i--, p += 2)
						match =
						    mtag->m_tag_id >= p[0] &&
						    mtag->m_tag_id <= p[1];
				}*/
				break;
			}

			/*
			 * The second set of opcodes represents 'actions',
			 * i.e. the terminal part of a rule once the packet
			 * matches all previous patterns.
			 * Typically there is only one action for each rule,
			 * and the opcode is stored at the end of the rule
			 * (but there are exceptions -- see below).
			 *
			 * In general, here we set retval and terminate the
			 * outer loop (would be a 'break 3' in some language,
			 * but we need to set l=0, done=1)
			 *
			 * Exceptions:
			 * O_COUNT and O_SKIPTO actions:
			 *   instead of terminating, we jump to the next rule
			 *   (setting l=0), or to the SKIPTO target (setting
			 *   f/f_len, cmd and l as needed), respectively.
			 *
			 * O_TAG, O_LOG and O_ALTQ action parameters:
			 *   perform some action and set match = 1;
			 *
			 * O_LIMIT and O_KEEP_STATE: these opcodes are
			 *   not real 'actions', and are stored right
			 *   before the 'action' part of the rule.
			 *   These opcodes try to install an entry in the
			 *   state tables; if successful, we continue with
			 *   the next opcode (match=1; break;), otherwise
			 *   the packet must be dropped (set retval,
			 *   break loops with l=0, done=1)
			 *
			 * O_PROBE_STATE and O_CHECK_STATE: these opcodes
			 *   cause a lookup of the state table, and a jump
			 *   to the 'action' part of the parent rule
			 *   if an entry is found, or
			 *   (CHECK_STATE only) a jump to the next rule if
			 *   the entry is not found.
			 *   The result of the lookup is cached so that
			 *   further instances of these opcodes become NOPs.
			 *   The jump to the next rule is done by setting
			 *   l=0, cmdlen=0.
			 */
			case O_LIMIT:
			case O_KEEP_STATE:
				//if (ipfw_install_state(f,
				  //  (ipfw_insn_limit *)cmd, args, tablearg)) {
					/* error or limit violation */
				//	retval = IP_FW_PORT_DENY_FLAG;
				//	l = 0;	/* exit inner loop */
				//	done = 1; /* exit outer loop */
				//}
				match = 1;
				break;

			case O_PROBE_STATE:
			case O_CHECK_STATE:
				/*
				 * dynamic rules are checked at the first
				 * keep-state or check-state occurrence,
				 * with the result being stored in dyn_dir.
				 * The compiler introduces a PROBE_STATE
				 * instruction for us when we have a
				 * KEEP_STATE (because PROBE_STATE needs
				 * to be run first).
				 */
				/*if (dyn_dir == MATCH_UNKNOWN &&
				    (q = ipfw_lookup_dyn_rule(&args->f_id,
				     &dyn_dir, proto == IPPROTO_TCP ?
					TCP(ulp) : NULL))
					!= NULL) {
					/*
					 * Found dynamic entry, update stats
					 * and jump to the 'action' part of
					 * the parent rule by setting
					 * f, cmd, l and clearing cmdlen.
					 */
					/*q->pcnt++;
					q->bcnt += pktlen;*/
					/* XXX we would like to have f_pos
					 * readily accessible in the dynamic
				         * rule, instead of having to
					 * lookup q->rule.
					 */
					/*f = q->rule;
					f_pos = ipfw_find_rule(chain,
						f->rulenum, f->id);
					cmd = ACTION_PTR(f);
					l = f->cmd_len - f->act_ofs;
					ipfw_dyn_unlock();
					cmdlen = 0;
					match = 1;
					break;
				}*/
				/*
				 * Dynamic entry not found. If CHECK_STATE,
				 * skip to next rule, if PROBE_STATE just
				 * ignore and continue with next opcode.
				 */
				if (cmd->opcode == O_CHECK_STATE)
					l = 0;	/* exit inner loop */
				match = 1;
				break;

			case O_ACCEPT:
				retval = 0;	/* accept */
				l = 0;		/* exit inner loop */
				done = 1;	/* exit outer loop */
				break;

			case O_PIPE:
			case O_QUEUE:
				/*set_match(args, f_pos, chain);
				args->rule.info = (cmd->arg1 == IP_FW_TABLEARG) ?
					tablearg : cmd->arg1;
				if (cmd->opcode == O_PIPE)
					args->rule.info |= IPFW_IS_PIPE;
				if (V_fw_one_pass)
					args->rule.info |= IPFW_ONEPASS;
				retval = IP_FW_DUMMYNET;*/
				l = 0;          /* exit inner loop */
				done = 1;       /* exit outer loop */
				break;

			case O_DIVERT:
			case O_TEE:
				//if (args->eh) /* not on layer 2 */
				    //break;
				/* otherwise this is terminal */
				l = 0;		/* exit inner loop */
				done = 1;	/* exit outer loop */
				retval = (cmd->opcode == O_DIVERT) ?
					IP_FW_DIVERT : IP_FW_TEE;
				//set_match(args, f_pos, chain);
				/*args->rule.info = (cmd->arg1 == IP_FW_TABLEARG) ?
				    tablearg : cmd->arg1;*/
				break;

			case O_COUNT:
				f->pcnt++;	/* update stats */
				f->bcnt += pktlen;
				f->timestamp = time_uptime;
				l = 0;		/* exit inner loop */
				break;

			case O_SKIPTO:
			    f->pcnt++;	/* update stats */
			    f->bcnt += pktlen;
			    f->timestamp = time_uptime;
			    /* If possible use cached f_pos (in f->next_rule),
			     * whose version is written in f->next_rule
			     * (horrible hacks to avoid changing the ABI).
			     */
			    if (cmd->arg1 != IP_FW_TABLEARG &&
				    (uintptr_t)f->x_next == chain->id) {
				f_pos = (uintptr_t)f->next_rule;
			    } else {
				int i = (cmd->arg1 == IP_FW_TABLEARG) ?
					tablearg : cmd->arg1;
				/* make sure we do not jump backward */
				if (i <= f->rulenum)
				    i = f->rulenum + 1;
				f_pos = ipfw_find_rule(chain, i, 0);
				/* update the cache */
				if (cmd->arg1 != IP_FW_TABLEARG) {
				    f->next_rule =
					(void *)(uintptr_t)f_pos;
				    f->x_next =
					(void *)(uintptr_t)chain->id;
				}
			    }
			    /*
			     * Skip disabled rules, and re-enter
			     * the inner loop with the correct
			     * f_pos, f, l and cmd.
			     * Also clear cmdlen and skip_or
			     */
			    for (; f_pos < chain->n_rules - 1 &&
				    (1 << chain->map[f_pos]->set);
				    f_pos++)
				;
			    /* prepare to enter the inner loop */
			    f = chain->map[f_pos];
			    l = f->cmd_len;
			    cmd = f->cmd;
			    match = 1;
			    cmdlen = 0;
			    skip_or = 0;
			    break;

			case O_REJECT:
				/*
				 * Drop the packet and send a reject notice
				 * if the packet is not ICMP (or is an ICMP
				 * query), and it is not multicast/broadcast.
				 */
				if (hlen > 0 && is_ipv4 && offset == 0 &&
				    (proto != IPPROTO_ICMP ||
				     is_icmp_query(ICMP(ulp))) &&
				    !(m->m_flags & (M_BCAST|M_MCAST)) &&
				    !IN_MULTICAST(ntohl(dst_ip.s_addr))) {
					//send_reject(args, cmd->arg1, iplen, ip);
					//m = args->m;
				}
				/* FALLTHROUGH */
#ifdef INET6
			case O_UNREACH6:
				if (hlen > 0 && is_ipv6 &&
				    ((offset & IP6F_OFF_MASK) == 0) &&
				    (proto != IPPROTO_ICMPV6 ||
				     (is_icmp6_query(icmp6_type) == 1)) &&
				    !(m->m_flags & (M_BCAST|M_MCAST)) &&
				    !IN6_IS_ADDR_MULTICAST(&args->f_id.dst_ip6)) {
					send_reject6(
					    args, cmd->arg1, hlen,
					    (struct ip6_hdr *)ip);
					m = args->m;
				}
				/* FALLTHROUGH */
#endif
			case O_DENY:
				retval = IP_FW_PORT_DENY_FLAG;
				l = 0;		/* exit inner loop */
				done = 1;	/* exit outer loop */
				break;

			case O_FORWARD_IP:
				//if (args->eh)	/* not valid on layer2 pkts */
				//	break;
				if (!q || dyn_dir == MATCH_FORWARD) {
				    struct sockaddr_in *sa;
				    sa = &(((ipfw_insn_sa *)cmd)->sa);
				    if (sa->sin_addr.s_addr == INADDR_ANY) {
					/*bcopy(sa, &args->hopstore,
							sizeof(*sa));
					args->hopstore.sin_addr.s_addr =
						    htonl(tablearg);
					args->next_hop = &args->hopstore;*/
				    } else {
					//args->next_hop = sa;
				    }
				}
				retval = IP_FW_PASS;
				l = 0;          /* exit inner loop */
				done = 1;       /* exit outer loop */
				break;

			case O_NETGRAPH:
			case O_NGTEE:
				//set_match(args, f_pos, chain);
				//args->rule.info = (cmd->arg1 == IP_FW_TABLEARG) ?
				//	tablearg : cmd->arg1;
				retval = (cmd->opcode == O_NETGRAPH) ?
				    IP_FW_NETGRAPH : IP_FW_NGTEE;
				l = 0;          /* exit inner loop */
				done = 1;       /* exit outer loop */
				break;

			case O_SETFIB:
				f->pcnt++;	/* update stats */
				f->bcnt += pktlen;
				f->timestamp = time_uptime;
				M_SETFIB(m, cmd->arg1);
				//args->f_id.fib = cmd->arg1;
				l = 0;		/* exit inner loop */
				break;

			case O_NAT:{
				// set_match(&rule, f_pos, chain);
 				   struct cfg_nat * t = ((ipfw_insn_nat *)cmd)->nat;
				    if (t == NULL) {
					int nat_id = (cmd->arg1 == IP_FW_TABLEARG) ?
						tablearg : cmd->arg1;
					t = (*lookup_nat_ptr)(&chain->nat, nat_id);

					if (t == NULL) {
					    retval = IP_FW_PORT_DENY_FLAG;
					    l = 0;	/* exit inner loop */
					    done = 1;	/* exit outer loop */
					    break;
					}
					if (cmd->arg1 != IP_FW_TABLEARG)
					    ((ipfw_insn_nat *)cmd)->nat = t;
				    }
				ipfw_nat_ptr(oif_arg, t, m);
				ip = mtod(m, struct ip*);
				retval = IP_FW_PASS;
				//ip->ip_src.s_addr = 17148096;//192.168.5.1
				memset(&ip_fwd, 0x00, sizeof(struct sockaddr_in));
                               	(*ip_fw_fwd_addr) = &ip_fwd;
				(*ip_fw_fwd_addr)->sin_addr = ip->ip_dst;
                                (*ip_fw_fwd_addr)->sin_family = AF_INET;
				l = 0;          /* exit inner loop */
				done = 1;       /* exit outer loop */
				break;
			}
			case O_REASS: {
				int ip_off;

				f->pcnt++;
				f->bcnt += pktlen;
				l = 0;	/* in any case exit inner loop */
				ip_off = ntohs(ip->ip_off);

				/* if not fragmented, go to next rule */
				if ((ip_off & (IP_MF | IP_OFFMASK)) == 0)
				    break;
				/*
				 * ip_reass() expects len & off in host
				 * byte order.
				 */
				SET_HOST_IPLEN(ip);

				//KOS TODO uncomment! m_arg = m_arg = ip_reass(m_arg);

				/*
				 * do IP header checksum fixup.
				 */
				if (m_arg == NULL) { /* fragment got swallowed */
				    retval = IP_FW_PORT_DENY_FLAG;
				} else { /* good, packet complete */
				    int hlen;

				    ip = mtod(*m_arg, struct ip *);
				    hlen = ip->ip_hl << 2;
				    SET_NET_IPLEN(ip);
				    ip->ip_sum = 0;
				    if (hlen == sizeof(struct ip))
					ip->ip_sum = in_cksum_hdr(ip);
				    else
					ip->ip_sum = in_cksum(m_arg, hlen);
				    retval = IP_FW_REASS;
				    //set_match(args, f_pos, chain);
				}
				done = 1;	/* exit outer loop */
				break;
			}

			default:
				panic("-- unknown opcode %d\n", cmd->opcode);
			} /* end of switch() on opcodes */
			/*
			 * if we get here with l=0, then match is irrelevant.
			 */

			if (cmd->len & F_NOT)
				match = !match;

			if (match) {
				if (cmd->len & F_OR)
					skip_or = 1;
			} else {
				if (!(cmd->len & F_OR)) /* not an OR block, */
					break;		/* try next rule    */
			}

		}	/* end of inner loop, scan opcodes */

		if (done)
			break;

/* next_rule:; */	/* try next rule		*/
	}		/* end of outer for, scan rules */

	if (done) {
		struct ip_fw *rule = chain->map[f_pos];
		/* Update statistics */
		rule->pcnt++;
		rule->bcnt += pktlen;
		rule->timestamp = time_uptime;
	} else {
		retval = IP_FW_PORT_DENY_FLAG;

	}
	pthread_mutex_destroy(&mutex);
	return (retval);

pullup_failed:
	return (IP_FW_PORT_DENY_FLAG);
}

int
vnet_ipfw_init()
{
	int error;
	struct ip_fw *rule = NULL;
	struct ip_fw_chain *chain;

	chain = &layer3_chain;

	/* First set up some values that are compile time options */
	V_autoinc_step = 100;	/* bounded to 1..1000 in add_rule() */
	//V_fw_deny_unknown_exthdrs = 1;

#ifdef IPFIREWALL_NAT
	LIST_INIT(&chain->nat);
#endif

	/* insert the default rule and create the initial map */
	chain->n_rules = 1;
	chain->static_len = sizeof(struct ip_fw) * 10; //TODO MAGIC
	chain->map = malloc(sizeof(struct ip_fw *), M_IPFW, M_NOWAIT | M_ZERO);
	if (chain->map)
		rule = malloc(chain->static_len, M_IPFW, M_NOWAIT | M_ZERO);
	if (rule == NULL) {
		if (chain->map)
			free(chain->map, M_IPFW);
		printf("ipfw2: ENOSPC initializing default rule "
			"(support disabled)\n");
		return (ENOSPC);
	}
	error = ipfw_init_tables(chain);
	if (error) {
		panic("init_tables"); /* XXX Marko fix this ! */
	}

	/* fill and insert the default rule */
	rule->act_ofs = 0;
	rule->rulenum = IPFW_DEFAULT_RULE;
	rule->cmd_len = 1;
	rule->set = RESVD_SET;
	rule->cmd[0].len = 1;
	rule->cmd[0].opcode = default_to_accept ? O_ACCEPT : O_DENY;
	chain->rules = chain->default_rule = chain->map[0] = rule;
	chain->id = rule->id = 1;

	//IPFW_LOCK_INIT(chain);
	//ipfw_dyn_init();

	/* First set up some values that are compile time options */
	//V_ipfw_vnet_ready = 1;		/* Open for business */

	/*
	 * Hook the sockopt handler, and the layer2 (V_ip_fw_chk_ptr)
	 * and pfil hooks for ipv4 and ipv6. Even if the latter two fail
	 * we still keep the module alive because the sockopt and
	 * layer2 paths are still useful.
	 * ipfw[6]_hook return 0 on success, ENOENT on failure,
	 * so we can ignore the exact return value and just set a flag.
	 *
	 * Note that V_fw[6]_enable are manipulated by a SYSCTL_PROC so
	 * changes in the underlying (per-vnet) variables trigger
	 * immediate hook()/unhook() calls.
	 * In layer2 we have the same behaviour, except that V_ether_ipfw
	 * is checked on each packet because there are no pfil hooks.
	 */
	//V_ip_fw_ctl_ptr = ipfw_ctl;
	ip_fw_chk_ptr = ipfw_chk;
	//error = ipfw_attach_hooks(1);
	return (error);
}
