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

extern int V_autoinc_step;

int
ipfw_find_rule(struct ip_fw_chain *chain, uint32_t key, uint32_t id)
{
	int i, lo, hi;
	struct ip_fw *r;

  	for (lo = 0, hi = chain->n_rules - 1; lo < hi;) {
		i = (lo + hi) / 2;
		r = chain->map[i];
		if (r->rulenum < key)
			lo = i + 1;	/* continue from the next one */
		else if (r->rulenum > key)
			hi = i;		/* this might be good */
		else if (r->id < id)
			lo = i + 1;	/* continue from the next one */
		else /* r->id >= id */
			hi = i;		/* this might be good */
	};
	return hi;
}


/*
 * allocate a new map, returns the chain locked. extra is the number
 * of entries to add or delete.
 */
static struct ip_fw **
get_map(struct ip_fw_chain *chain, int extra, int locked)
{

	for (;;) {
		struct ip_fw **map;
		int i;

		i = chain->n_rules + extra;
		map = malloc(i * sizeof(struct ip_fw *), M_IPFW,
			locked ? M_NOWAIT : M_WAITOK);
		if (map == NULL) {
			printf("%s: cannot allocate map\n", __FUNCTION__);
			return NULL;
		}
		if (!locked)
			IPFW_UH_WLOCK(chain);
		if (i >= chain->n_rules + extra) /* good */
			return map;
		/* otherwise we lost the race, free and retry */
		if (!locked)
			IPFW_UH_WUNLOCK(chain);
		free(map, M_IPFW);
	}
}

/*
 * swap the maps. It is supposed to be called with IPFW_UH_WLOCK
 */
static struct ip_fw **
swap_map(struct ip_fw_chain *chain, struct ip_fw **new_map, int new_len)
{
	struct ip_fw **old_map;

	IPFW_WLOCK(chain);
	chain->id++;
	chain->n_rules = new_len;
	old_map = chain->map;
	chain->map = new_map;
	IPFW_WUNLOCK(chain);
	return old_map;
}

/*
 * Add a new rule to the list. Copy the rule into a malloc'ed area, then
 * possibly create a rule number and add the rule to the list.
 * Update the rule_number in the input struct so the caller knows it as well.
 * XXX DO NOT USE FOR THE DEFAULT RULE.
 * Must be called without IPFW_UH held
 */
int
ipfw_add_rule(struct ip_fw_chain *chain, struct ip_fw *input_rule)
{
	struct ip_fw *rule;
	int i, l, insert_before;
	struct ip_fw **map;	/* the new array of pointers */

	if (chain->rules == NULL || input_rule->rulenum > IPFW_DEFAULT_RULE-1)
		return (EINVAL);

	l = RULESIZE(input_rule);
	rule = malloc(l, M_IPFW, M_WAITOK | M_ZERO);
	if (rule == NULL)
		return (ENOSPC);
	/* get_map returns with IPFW_UH_WLOCK if successful */
	map = get_map(chain, 1, 0 /* not locked */);
	if (map == NULL) {
		free(rule, M_IPFW);
		return ENOSPC;
	}

	bcopy(input_rule, rule, l);
	/* clear fields not settable from userland */
	rule->x_next = NULL;
	rule->next_rule = NULL;
	rule->pcnt = 0;
	rule->bcnt = 0;
	rule->timestamp = 0;

	if (V_autoinc_step < 1)
		V_autoinc_step = 1;
	else if (V_autoinc_step > 1000)
		V_autoinc_step = 1000;
	/* find the insertion point, we will insert before */
	insert_before = rule->rulenum ? rule->rulenum + 1 : IPFW_DEFAULT_RULE;
	i = ipfw_find_rule(chain, insert_before, 0);
	/* duplicate first part */
	if (i > 0)
		bcopy(chain->map, map, i * sizeof(struct ip_fw *));
	map[i] = rule;
	/* duplicate remaining part, we always have the default rule */
	bcopy(chain->map + i, map + i + 1,
		sizeof(struct ip_fw *) *(chain->n_rules - i));
	if (rule->rulenum == 0) {
		/* write back the number */
		rule->rulenum = i > 0 ? map[i-1]->rulenum : 0;
		if (rule->rulenum < IPFW_DEFAULT_RULE - V_autoinc_step)
			rule->rulenum += V_autoinc_step;
		input_rule->rulenum = rule->rulenum;
	}

	rule->id = chain->id + 1;
	map = swap_map(chain, map, chain->n_rules + 1);
	chain->static_len += l;
	IPFW_UH_WUNLOCK(chain);
	if (map)
		free(map, M_IPFW);
	return (0);
}

