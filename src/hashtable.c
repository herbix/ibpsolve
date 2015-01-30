#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

#include "hashtable.h"

struct ht_entry {
	void *key;
	void *value;
	struct ht_entry *next;
};

struct hashtable {
	struct ht_entry **table;
	int capacity;
	hashcode_getter hcg;
	equal_checker eqc;
};

struct hashtable *ht_init(int capacity, hashcode_getter hcg, equal_checker eqc)
{
	struct hashtable *ht = (struct hashtable*)malloc(sizeof(struct hashtable));
	ht->capacity = capacity;
	ht->table = (struct ht_entry**)malloc(sizeof(struct ht_entry*) * capacity);
	memset(ht->table, 0, sizeof(struct ht_entry*) * capacity);
	ht->hcg = hcg;
	ht->eqc = eqc;
	return ht;
}

struct hashtable *ht_destroy(struct hashtable *ht)
{
	int i;
	for(i=0; i<ht->capacity; i++) {
		struct ht_entry *p = ht->table[i];
		while(p != NULL) {
			struct ht_entry *q = p;
			p = p->next;
			free(q);
		}
	}
	free(ht->table);
	free(ht);
	return NULL;
}

static struct ht_entry *get_entry(struct hashtable *ht, const void *key, int *opos)
{
	int pos = ht->hcg(key) % ht->capacity;
	struct ht_entry *p = ht->table[pos];

	while(p != NULL) {
		if(ht->eqc(p->key, key)) {
			break;
		}
		p = p->next;
	}

	if(opos != NULL) {
		*opos = pos;
	}

	return p;
}

bool ht_put(struct hashtable *ht, void *key, void *value)
{
	int pos;
	struct ht_entry *p = get_entry(ht, key, &pos);
	bool r = (p != NULL);

	if(r) {
		p->value = value;
	} else {
		p = (struct ht_entry*)malloc(sizeof(struct ht_entry));
		p->key = key;
		p->value = value;
		p->next = ht->table[pos];
		ht->table[pos] = p;
	}

	return r;
}

void *ht_get(struct hashtable *ht, const void *key)
{
	struct ht_entry *p = get_entry(ht, key, NULL);
	return p == NULL ? NULL : p->value;
}

void *ht_get_key(struct hashtable *ht, const void *key)
{
	struct ht_entry *p = get_entry(ht, key, NULL);
	return p == NULL ? NULL : p->key;
}

void *ht_remove(struct hashtable *ht, void *key)
{
	int pos = ht->hcg(key) % ht->capacity;
	struct ht_entry *p = ht->table[pos];
	struct ht_entry *q = NULL;
	void *value;

	while(p != NULL) {
		if(ht->eqc(p->key, key)) {
			break;
		}
		q = p;
		p = p->next;
	}

	if(p == NULL) {
		return NULL;
	}

	if(q == NULL) {
		ht->table[pos] = p->next;
	} else {
		q->next = p->next;
	}

	value = p->value;
	free(p);
	return value;
}

bool ht_contains(struct hashtable *ht, void *key)
{
	return get_entry(ht, key, NULL) != NULL;
}

void ht_traverse(struct hashtable *ht, hashtable_iterator it, void *data)
{
	int i;
	for(i=0; i<ht->capacity; i++) {
		struct ht_entry *p = ht->table[i];
		struct ht_entry *q = NULL;
		while(p != NULL) {
			enum ht_traverse_action a = it(p->key, p->value, data);
			struct ht_entry *t = p->next;
			switch(a) {
				case NO_ACTION:
					break;
				case REMOVE_ITEM:
					if(q == NULL) {
						ht->table[i] = p->next;
					} else {
						q->next = p->next;
					}
					free(p);
					p = q;
					break;
				case FINISH_TRAVERSE:
					return;
			}
			q = p;
			p = t;
		}
	}
}

