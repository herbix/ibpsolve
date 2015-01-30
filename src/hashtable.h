#ifndef _HASHTABLE_H_
#define _HASHTABLE_H_

#include "def.h"

struct hashtable;

enum ht_traverse_action {
	NO_ACTION,
	REMOVE_ITEM,
	FINISH_TRAVERSE
};

typedef unsigned (*hashcode_getter) (const void*);
typedef bool (*equal_checker) (const void*, const void*);
typedef enum ht_traverse_action (*hashtable_iterator) (void* key, void* value, void* data);

struct hashtable *ht_init(int capacity, hashcode_getter hcg, equal_checker eqc);
struct hashtable *ht_destroy(struct hashtable *ht);

bool ht_put(struct hashtable *ht, void *key, void *value);
void *ht_get(struct hashtable *ht, const void *key);
void *ht_get_key(struct hashtable *ht, const void *key);
void *ht_remove(struct hashtable *ht, void *key);
bool ht_contains(struct hashtable *ht, void *key);

void ht_traverse(struct hashtable *ht, hashtable_iterator it, void *data);

#endif
