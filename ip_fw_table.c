#define MAXHOSTNAMELEN  256             /* max hostname size */
#include <sys/param.h>
#include <sys/malloc.h>
//#include <sys/kernel.h>
#include <sys/socket.h>
#include <net/radix.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip_var.h>	/* struct ipfw_rule_ref */
#include <netinet/ip_fw.h>
#include <sys/queue.h> /* LIST_HEAD */
#include "ip_fw_private.h"

#define in_nullhost(x)  ((x).s_addr == INADDR_ANY)
/*
 * Find First Set bit
 */
int
ffs(int mask)
{
    int bit;
    if (mask == 0)
        return (0);
    for (bit = 1; !(mask & 1); bit++)
        mask = (unsigned int)mask >> 1;
    return (bit);
}

//MALLOC_DEFINE(M_FTABLE, "ipfw_tbl", "IpFw tables");

struct table_entry {
	struct radix_node	rn[2];
	struct sockaddr_in	addr, mask;
	u_int32_t		value;
};

/*
 * The radix code expects addr and mask to be array of bytes,
 * with the first byte being the length of the array. rn_inithead
 * is called with the offset in bits of the lookup key within the
 * array. If we use a sockaddr_in as the underlying type,
 * sin_len is conveniently located at offset 0, sin_addr is at
 * offset 4 and normally aligned.
 * But for portability, let's avoid assumption and make the code explicit
 */
#define KEY_LEN(v)	*((uint8_t *)&(v))
#define KEY_OFS		(8*offsetof(struct sockaddr_in, sin_addr))

int
ipfw_add_table_entry(struct ip_fw_chain *ch, uint16_t tbl, in_addr_t addr,
    uint8_t mlen, uint32_t value)
{
	struct radix_node_head *rnh;
	struct table_entry *ent;
	struct radix_node *rn;

	if (tbl >= IPFW_TABLES_MAX)
		return (EINVAL);
	rnh = ch->tables[tbl];
	ent = malloc(sizeof(*ent), M_FTABLE, M_NOWAIT | M_ZERO);
	if (ent == NULL)
		return (ENOMEM);
	ent->value = value;
	KEY_LEN(ent->addr) = KEY_LEN(ent->mask) = 8;
	ent->mask.sin_addr.s_addr = htonl(mlen ? ~((1 << (32 - mlen)) - 1) : 0);
	ent->addr.sin_addr.s_addr = addr & ent->mask.sin_addr.s_addr;
	//IPFW_WLOCK(ch);
	rn = rnh->rnh_addaddr(&ent->addr, &ent->mask, rnh, (void *)ent);
	if (rn == NULL) {
		//IPFW_WUNLOCK(ch);
		free(ent, M_FTABLE);
		return (EEXIST);
	}
	//IPFW_WUNLOCK(ch);
	return (0);
}

int
ipfw_del_table_entry(struct ip_fw_chain *ch, uint16_t tbl, in_addr_t addr,
    uint8_t mlen)
{
	struct radix_node_head *rnh;
	struct table_entry *ent;
	struct sockaddr_in sa, mask;

	if (tbl >= IPFW_TABLES_MAX)
		return (EINVAL);
	rnh = ch->tables[tbl];
	KEY_LEN(sa) = KEY_LEN(mask) = 8;
	mask.sin_addr.s_addr = htonl(mlen ? ~((1 << (32 - mlen)) - 1) : 0);
	sa.sin_addr.s_addr = addr & mask.sin_addr.s_addr;
	//IPFW_WLOCK(ch);
	ent = (struct table_entry *)rnh->rnh_deladdr(&sa, &mask, rnh);
	if (ent == NULL) {
	//	IPFW_WUNLOCK(ch);
		return (ESRCH);
	}
	//IPFW_WUNLOCK(ch);
	free(ent, M_FTABLE);
	return (0);
}

static int
flush_table_entry(struct radix_node *rn, void *arg)
{
	struct radix_node_head * const rnh = arg;
	struct table_entry *ent;

	ent = (struct table_entry *)
	    rnh->rnh_deladdr(rn->rn_key, rn->rn_mask, rnh);
	if (ent != NULL)
		free(ent, M_FTABLE);
	return (0);
}

int
ipfw_flush_table(struct ip_fw_chain *ch, uint16_t tbl)
{
	struct radix_node_head *rnh;

	//IPFW_WLOCK_ASSERT(ch);

	if (tbl >= IPFW_TABLES_MAX)
		return (EINVAL);
	rnh = ch->tables[tbl];
	//KASSERT(rnh != NULL, ("NULL IPFW table"));
	rnh->rnh_walktree(rnh, flush_table_entry, rnh);
	return (0);
}

void
ipfw_destroy_tables(struct ip_fw_chain *ch)
{
	uint16_t tbl;
	struct radix_node_head *rnh;

	//IPFW_WLOCK_ASSERT(ch);

	for (tbl = 0; tbl < IPFW_TABLES_MAX; tbl++) {
		ipfw_flush_table(ch, tbl);
		rnh = ch->tables[tbl];
		rn_detachhead((void **)&rnh);
	}
}

int
ipfw_init_tables(struct ip_fw_chain *ch)
{
	int i;
	uint16_t j;

	for (i = 0; i < IPFW_TABLES_MAX; i++) {
		if (!rn_inithead((void **)&ch->tables[i], KEY_OFS)) {
			for (j = 0; j < i; j++) {
				(void) ipfw_flush_table(ch, j);
			}
			return (ENOMEM);
		}
	}
	return (0);
}

int
ipfw_lookup_table(struct ip_fw_chain *ch, uint16_t tbl, in_addr_t addr,
    uint32_t *val)
{
	struct radix_node_head *rnh;
	struct table_entry *ent;
	struct sockaddr_in sa;

	if (tbl >= IPFW_TABLES_MAX)
		return (0);
	rnh = ch->tables[tbl];
	KEY_LEN(sa) = 8;
	sa.sin_addr.s_addr = addr;
	ent = (struct table_entry *)(rnh->rnh_lookup(&sa, NULL, rnh));
	if (ent != NULL) {
		*val = ent->value;
		return (1);
	}
	return (0);
}

static int
count_table_entry(struct radix_node *rn, void *arg)
{
	u_int32_t * const cnt = arg;

	(*cnt)++;
	return (0);
}

int
ipfw_count_table(struct ip_fw_chain *ch, uint32_t tbl, uint32_t *cnt)
{
	struct radix_node_head *rnh;

	if (tbl >= IPFW_TABLES_MAX)
		return (EINVAL);
	rnh = ch->tables[tbl];
	*cnt = 0;
	rnh->rnh_walktree(rnh, count_table_entry, cnt);
	return (0);
}

static int
dump_table_entry(struct radix_node *rn, void *arg)
{
	struct table_entry * const n = (struct table_entry *)rn;
	ipfw_table * const tbl = arg;
	ipfw_table_entry *ent;

	if (tbl->cnt == tbl->size)
		return (1);
	ent = &tbl->ent[tbl->cnt];
	ent->tbl = tbl->tbl;
	if (in_nullhost(n->mask.sin_addr))
		ent->masklen = 0;
	else
		ent->masklen = 33 - ffs(ntohl(n->mask.sin_addr.s_addr));
	ent->addr = n->addr.sin_addr.s_addr;
	ent->value = n->value;
	tbl->cnt++;
	return (0);
}

int
ipfw_dump_table(struct ip_fw_chain *ch, ipfw_table *tbl)
{
	struct radix_node_head *rnh;

	if (tbl->tbl >= IPFW_TABLES_MAX)
		return (EINVAL);
	rnh = ch->tables[tbl->tbl];
	tbl->cnt = 0;
	rnh->rnh_walktree(rnh, dump_table_entry, tbl);
	return (0);
}

