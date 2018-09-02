// SPDX-License-Identifier: GPL-2.0
/*
 * SLOB Allocator: Simple List Of Blocks
 *
 * Matt Mackall <mpm@selenic.com> 12/30/03
 *
 * NUMA support by Paul Mundt, 2007.
 *
 * How SLOB works:
 *
 * The core of SLOB is a traditional K&R style heap allocator, with
 * support for returning aligned objects. The granularity of this
 * allocator is as little as 2 bytes, however typically most architectures
 * will require 4 bytes on 32-bit and 8 bytes on 64-bit.
 *
 * The slob heap is a set of linked list of pages from alloc_pages(),
 * and within each page, there is a singly-linked list of free blocks
 * (slob_t). The heap is grown on demand. To reduce fragmentation,
 * heap pages are segregated into three lists, with objects less than
 * 256 bytes, objects less than 1024 bytes, and all other objects.
 *
 * Allocation from heap involves first searching for a page with
 * sufficient free blocks (using a next-fit-like approach) followed by
 * a first-fit scan of the page. Deallocation inserts objects back
 * into the free list in address order, so this is effectively an
 * address-ordered first fit.
 *
 * Above this is an implementation of kmalloc/kfree. Blocks returned
 * from kmalloc are prepended with a 4-byte header with the kmalloc size.
 * If kmalloc is asked for objects of PAGE_SIZE or larger, it calls
 * alloc_pages() directly, allocating compound pages so the page order
 * does not have to be separately tracked.
 * These objects are detected in kfree() because PageSlab()
 * is false for them.
 *
 * SLAB is emulated on top of SLOB by simply calling constructors and
 * destructors for every SLAB allocation. Objects are returned with the
 * 4-byte alignment unless the SLAB_HWCACHE_ALIGN flag is set, in which
 * case the low-level allocator will fragment blocks to create the proper
 * alignment. Again, objects of page-size or greater are allocated by
 * calling alloc_pages(). As SLAB objects know their size, no separate
 * size bookkeeping is necessary and there is essentially no allocation
 * space overhead, and compound pages aren't needed for multi-page
 * allocations.
 *
 * NUMA support in SLOB is fairly simplistic, pushing most of the real
 * logic down to the page allocator, and simply doing the node accounting
 * on the upper levels. In the event that a node id is explicitly
 * provided, __alloc_pages_node() with the specified node id is used
 * instead. The common case (or when the node id isn't explicitly provided)
 * will default to the current node, as per numa_node_id().
 *
 * Node aware pages are still inserted in to the global freelist, and
 * these are scanned for by matching against the node id encoded in the
 * page flags. As a result, block allocations that can be satisfied from
 * the freelist will only be done so on pages residing on the same node,
 * in order to prevent random node placement.
 */

#include <linux/kernel.h>
#include <linux/slab.h>

#include <linux/mm.h>
#include <linux/swap.h> /* struct reclaim_state */
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/kmemleak.h>

#include <trace/events/kmem.h>

#include <linux/atomic.h>

#include "slab.h"

#define KMALLOC_ALLOCATE    1
#define KMEM_CACHE_ALLOCATE 0
#define NUM_OF_SLOBA_LISTS 45

struct page_cache_head {
        void *freelist;
        unsigned short avail;   // available objects
        unsigned short counter;
        unsigned short size;
};

typedef unsigned int sloba_meta_data;
#define BYTES_OF_META_DATA (sizeof(sloba_meta_data))

inline static unsigned short meta_get_size(sloba_meta_data kmeta)
{
        return kmeta >> 16;
}

inline static unsigned short meta_get_delta(sloba_meta_data kmeta)
{
        return kmeta & 0x00ff;
}

inline static sloba_meta_data encode_sloba_meta_data(unsigned short size, unsigned short delta)
{
        return (sloba_meta_data)((size << 16) | (delta));
}

#define AVAILABLE_PER_PAGE (PAGE_SIZE - sizeof(struct page_cache_head))
#define GO_BUDDY_SYSTEM (AVAILABLE_PER_PAGE >> 1)

struct cache_array {
        union {
                void *head; // address of first page
                void *last; // last available page
        };
        unsigned short size;  // object size
};

struct sloba_lists {
        struct cache_array bins8[(128 / 8) + 1];    // ~ 128
        struct cache_array bins16[(128 / 16)];      // 144 ~ 256
        struct cache_array bins32[(256 / 32)];      // 288 ~ 512
        struct cache_array bins64[(256 / 64)];      // 576 ~ 768
        struct cache_array bins128[(256 / 128)];    // 896 ~ 1024
        struct cache_array bins512[(2048 / 512)];   // 1536 ~ 3072
        struct cache_array bins1024[(1024 / 1024)]; // 4096
        struct cache_array large;                   // 4096 ~
};

DEFINE_PER_CPU(struct sloba_lists, sloba_slabs);

static unsigned short cache_sizes[] = {
        0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128,
        144, 160, 176, 192, 208, 224, 240, 256, 288, 320, 352, 384, 416,
        448, 480, 512, 576, 640, 704, 768, 896, 1024, 1536, 2048, 2560,
        3072, 4096, 10000
};

static inline char *page_cache_get_head(struct page_cache_head *p)
{
        return (char *)(&p[1]);
}

static int bins_index(size_t size)
{
        if (size <=          8) return 1;
	if (size <=         16) return 2;
	if (size <=         24) return 3;
	if (size <=         32) return 4;
	if (size <=         40) return 5;
	if (size <=         48) return 6;
	if (size <=         56) return 7;
	if (size <=         64) return 8;
	if (size <=         72) return 9;
	if (size <=         80) return 10;
	if (size <=         88) return 11;
	if (size <=         96) return 12;
	if (size <=        104) return 13;
	if (size <=        112) return 14;
	if (size <=        120) return 15;
	if (size <=        128) return 16;
	if (size <=        144) return 17;
	if (size <=        160) return 18;
	if (size <=        176) return 19;
	if (size <=        192) return 20;
	if (size <=        208) return 21;
	if (size <=        224) return 22;
	if (size <=        240) return 23;
	if (size <=        256) return 24;
        if (size <=        288) return 25;
	if (size <=        320) return 26;
	if (size <=        352) return 27;
	if (size <=        384) return 28;
	if (size <=        416) return 29;
	if (size <=        448) return 30;
	if (size <=        480) return 31;
	if (size <=        512) return 32;
	if (size <=        576) return 33;
	if (size <=        640) return 34;
	if (size <=        704) return 35;
	if (size <=        768) return 36;
	if (size <=        896) return 37;
	if (size <=       1024) return 38;
	if (size <=       1536) return 39;
	if (size <=       2048) return 40;
	if (size <=       2560) return 41;
	if (size <=       3072) return 42;
        if (size <=       4096) return 43;
        return 44;
}

static struct cache_array *get_proper_sloba_list(size_t size)
{
        struct sloba_lists *sloba_lists;
        int index = bins_index(size);
        sloba_lists = &per_cpu(sloba_slabs, smp_processor_id());
        return (((struct cache_array *)sloba_lists) + index);
}

static inline void page_head_init(struct page_cache_head *head, unsigned short cache_size)
{
        head->freelist = NULL;
        head->avail = (AVAILABLE_PER_PAGE / cache_size);
        head->counter = 0;
        head->size = cache_size;
}

/*
 * slob_page_free: true for pages on free_slob_pages list.
 */
static inline int slob_page_free(struct page *sp)
{
	return PageSlobFree(sp);
}

static inline void clear_slob_page_free(struct page *sp)
{
	__ClearPageSlobFree(sp);
}

/*
 * struct slob_rcu is inserted at the tail of allocated slob blocks, which
 * were created with a SLAB_TYPESAFE_BY_RCU slab. slob_rcu is used to free
 * the block using call_rcu.
 */
struct slob_rcu {
	struct rcu_head head;
	int size;
};

/*
 * slob_lock protects all slob allocator structures.
 */
static DEFINE_SPINLOCK(slob_lock);

static void *slob_new_pages(gfp_t gfp, int order, int node)
{
	void *page;

#ifdef CONFIG_NUMA
	if (node != NUMA_NO_NODE)
		page = __alloc_pages_node(node, gfp, order);
	else
#endif
		page = alloc_pages(gfp, order);

	if (!page)
		return NULL;

	return page_address(page);
}

static inline void mark_dead_flag(struct page_cache_head *page_head)
{
        page_head->avail = 0xDEAD;
}

static inline char is_dead_page(struct page_cache_head *page_head)
{
        return page_head->avail == 0xDEAD;
}

static void slob_free_pages(void *b, int order)
{
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += 1 << order;
	free_pages((unsigned long)b, order);
}

static void *sloba_alloc_from_freelist(struct page_cache_head *page_head, size_t size)
{
        // available space is found in freelist
        if(page_head->freelist){
                void *ret = page_head->freelist;
                page_head->freelist = *(void **)ret;
                return ret;
        }
        return NULL;
}

static void *cache_array_init_firstpage(struct cache_array *ca, gfp_t gfp, int node)
{
        unsigned long flags;
        // allocate new page
        ca->head = slob_new_pages(gfp & ~__GFP_ZERO, 0, node);
        // if buddy system failed to allocate new page, return NULL
        if (!ca->head)
                return NULL;
        spin_lock_irqsave(&slob_lock, flags);
        page_head_init((struct page_cache_head *)ca->head, ca->size);
        __SetPageSlab(virt_to_page(ca->head));
        __SetPageSlobFree(virt_to_page(ca->head));
        spin_unlock_irqrestore(&slob_lock, flags);
        return ca->head;
}

static void *sloba_alloc_new_page(struct page_cache_head *page_head, gfp_t gfp, int node, size_t size)
{
        struct page_cache_head *ret;
        unsigned long flags;
        
        // next page has not been allocated yet, so allocate it
        ret = slob_new_pages(gfp & ~__GFP_ZERO, 0, node);

        spin_lock_irqsave(&slob_lock, flags);
        page_head_init((struct page_cache_head *)ret, size);
        mark_dead_flag(page_head);
        
        __SetPageSlab(virt_to_page(ret));
        __SetPageSlobFree(virt_to_page(ret));
        spin_unlock_irqrestore(&slob_lock, flags);

        return ret;
}

static void *slob_alloc(size_t size, gfp_t gfp, int align, int node, char way)
{
	void *b = NULL;
        void *ret = NULL;
        unsigned long flags;
        size_t aligned_size = size + align;
        struct cache_array *sloba_cache = get_proper_sloba_list(aligned_size);
        struct page_cache_head *page_head;
        
        /*
         * this cache_array is not initialized
         */
        if(!sloba_cache->head)
                if(!cache_array_init_firstpage(sloba_cache, gfp, node))
                        return NULL;

        spin_lock_irqsave(&slob_lock, flags);
        // we'll allocate slab from this page
        page_head = sloba_cache->last;

        if((b = sloba_alloc_from_freelist(page_head, sloba_cache->size))){
                spin_unlock_irqrestore(&slob_lock, flags);
                goto done;
        }
        spin_unlock_irqrestore(&slob_lock, flags);
        
        // if this page is not available, find available page
        if(!page_head->avail)
                page_head = sloba_cache->last = sloba_alloc_new_page(page_head, gfp, node, sloba_cache->size);
        
        // get slab from back
        b = (void *)(page_cache_get_head(page_head) + (sloba_cache->size * (--page_head->avail)));

done:
        spin_lock_irqsave(&slob_lock, flags);
        page_head->counter++;
        ret = (void *)ALIGN((unsigned long)b + BYTES_OF_META_DATA, align);

        *((sloba_meta_data *)ret - 1) = encode_sloba_meta_data(size - BYTES_OF_META_DATA, (unsigned short)(ret - b));

	if (unlikely(gfp & __GFP_ZERO))
		memset(ret, 0, size - BYTES_OF_META_DATA);

        spin_unlock_irqrestore(&slob_lock, flags);
        
	return ret;
}

static void slob_free(void *block, int size)
{
        struct page_cache_head *page_head;
        unsigned long flags;
        
	if (unlikely(ZERO_OR_NULL_PTR(block)))
		return;
	BUG_ON(!size);
        
        spin_lock_irqsave(&slob_lock, flags);

        page_head = (struct page_cache_head *)((unsigned long)block & PAGE_MASK);
        page_head->counter--;
        if(is_dead_page(page_head)){
                if(!page_head->counter){
                        struct page *sp = virt_to_page(page_head);
                        if (slob_page_free(sp))
                                clear_slob_page_free(sp);
                        spin_unlock_irqrestore(&slob_lock, flags);
                        __ClearPageSlab(sp);
                        page_mapcount_reset(sp);
                        slob_free_pages(page_head, 0);
                        return;
                }
        }else{
                *(void **)block = page_head->freelist;
                page_head->freelist = block;
        }
        
        spin_unlock_irqrestore(&slob_lock, flags);
}

/*
 * End of slob allocator proper. Begin kmem_cache_alloc and kmalloc frontend.
 */
static __always_inline void *
__do_kmalloc_node(size_t size, gfp_t gfp, int node, unsigned long caller)
{
        int align = max_t(size_t, ARCH_KMALLOC_MINALIGN, ARCH_SLAB_MINALIGN);
        size_t aligned = (size + BYTES_OF_META_DATA);
	void *ret;

	gfp &= gfp_allowed_mask;

	fs_reclaim_acquire(gfp);
	fs_reclaim_release(gfp);

	if (aligned < GO_BUDDY_SYSTEM) {
		if (!size)
			return ZERO_SIZE_PTR;

		ret = slob_alloc(aligned, gfp, align, node, KMALLOC_ALLOCATE);

		if (!ret)
			return NULL;
                
		trace_kmalloc_node(caller, ret,
				   size, aligned, gfp, node);
	} else {
		unsigned int order = get_order(size);

		if (likely(order))
			gfp |= __GFP_COMP;
		ret = slob_new_pages(gfp, order, node);
                
		trace_kmalloc_node(caller, ret,
				   size, PAGE_SIZE << order, gfp, node);
	}

	kmemleak_alloc(ret, size, 1, gfp);
	return ret;
}

void *__kmalloc(size_t size, gfp_t gfp)
{
	return __do_kmalloc_node(size, gfp, NUMA_NO_NODE, _RET_IP_);
}
EXPORT_SYMBOL(__kmalloc);

void *__kmalloc_track_caller(size_t size, gfp_t gfp, unsigned long caller)
{
	return __do_kmalloc_node(size, gfp, NUMA_NO_NODE, caller);
}

#ifdef CONFIG_NUMA
void *__kmalloc_node_track_caller(size_t size, gfp_t gfp,
					int node, unsigned long caller)
{
	return __do_kmalloc_node(size, gfp, node, caller);
}
#endif

void kfree(const void *block)
{
	struct page *sp;

	trace_kfree(_RET_IP_, block);

	if (unlikely(ZERO_OR_NULL_PTR(block)))
		return;
	kmemleak_free(block);

	sp = virt_to_page(block);
	if (PageSlab(sp)) {
                sloba_meta_data *meta = (sloba_meta_data *)((void *)block - BYTES_OF_META_DATA);
		slob_free(block - meta_get_delta(*meta), ksize(block) + BYTES_OF_META_DATA);
	} else
		__free_pages(sp, compound_order(sp));
}
EXPORT_SYMBOL(kfree);

/* can't use ksize for kmem_cache_alloc memory, only kmalloc */
size_t ksize(const void *block)
{
	struct page *sp;
	size_t size;
	sloba_meta_data *m;

	BUG_ON(!block);
	if (unlikely(block == ZERO_SIZE_PTR))
		return 0;

	sp = virt_to_page(block);
	if (unlikely(!PageSlab(sp)))
		return PAGE_SIZE << compound_order(sp);

        m = (sloba_meta_data *)((void *)block - BYTES_OF_META_DATA);
        size = meta_get_size(*m);
	return size;
}
EXPORT_SYMBOL(ksize);

int __kmem_cache_create(struct kmem_cache *c, slab_flags_t flags)
{
	if (flags & SLAB_TYPESAFE_BY_RCU) {
		/* leave room for rcu footer at the end of object */
		c->size += sizeof(struct slob_rcu);
	}
	c->flags = flags;
	return 0;
}

static void *slob_alloc_node(struct kmem_cache *c, gfp_t flags, int node)
{
	void *b;

	flags &= gfp_allowed_mask;

	fs_reclaim_acquire(flags);
	fs_reclaim_release(flags);

	if (c->size < GO_BUDDY_SYSTEM) {
                if(!c->size)
                        return ZERO_SIZE_PTR;
		b = slob_alloc(c->size + BYTES_OF_META_DATA, flags, c->align, node, KMEM_CACHE_ALLOCATE);
		trace_kmem_cache_alloc_node(_RET_IP_, b, c->object_size,
					    c->size,
					    flags, node);
	} else {
		b = slob_new_pages(flags, get_order(c->size), node);
		trace_kmem_cache_alloc_node(_RET_IP_, b, c->object_size,
					    PAGE_SIZE << get_order(c->size),
					    flags, node);
	}

	if (b && c->ctor)
		c->ctor(b);

	kmemleak_alloc_recursive(b, c->size, 1, c->flags, flags);
	return b;
}

void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	return slob_alloc_node(cachep, flags, NUMA_NO_NODE);
}
EXPORT_SYMBOL(kmem_cache_alloc);

#ifdef CONFIG_NUMA
void *__kmalloc_node(size_t size, gfp_t gfp, int node)
{
	return __do_kmalloc_node(size, gfp, node, _RET_IP_);
}
EXPORT_SYMBOL(__kmalloc_node);

void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t gfp, int node)
{
	return slob_alloc_node(cachep, gfp, node);
}
EXPORT_SYMBOL(kmem_cache_alloc_node);
#endif

static void __kmem_cache_free(void *b, int size)
{
	if (size < GO_BUDDY_SYSTEM){
                sloba_meta_data *kmeta = (sloba_meta_data *)((void *)b - BYTES_OF_META_DATA);
		slob_free(b - meta_get_delta(*kmeta), size);
        }else
		slob_free_pages(b, get_order(size));
}

static void kmem_rcu_free(struct rcu_head *head)
{
	struct slob_rcu *slob_rcu = (struct slob_rcu *)head;
	void *b = (void *)slob_rcu - (slob_rcu->size - sizeof(struct slob_rcu));
	__kmem_cache_free(b, slob_rcu->size);
}

void kmem_cache_free(struct kmem_cache *c, void *b)
{
	kmemleak_free_recursive(b, c->flags);
	if (unlikely(c->flags & SLAB_TYPESAFE_BY_RCU)) {
		struct slob_rcu *slob_rcu;
		slob_rcu = b + (c->size - sizeof(struct slob_rcu));
		slob_rcu->size = c->size;
		call_rcu(&slob_rcu->head, kmem_rcu_free);
	} else {
		__kmem_cache_free(b, c->size);
	}

	trace_kmem_cache_free(_RET_IP_, b);
}
EXPORT_SYMBOL(kmem_cache_free);

void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
{
	__kmem_cache_free_bulk(s, size, p);
}
EXPORT_SYMBOL(kmem_cache_free_bulk);

int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size, void **p)
{
	return __kmem_cache_alloc_bulk(s, flags, size, p);
}
EXPORT_SYMBOL(kmem_cache_alloc_bulk);

int __kmem_cache_shutdown(struct kmem_cache *c)
{
	/* No way to check for remaining objects */
	return 0;
}

void __kmem_cache_release(struct kmem_cache *c)
{
}

int __kmem_cache_shrink(struct kmem_cache *d)
{
	return 0;
}

struct kmem_cache kmem_cache_boot = {
	.name = "kmem_cache",
	.size = sizeof(struct kmem_cache),
	.flags = SLAB_PANIC,
	.align = ARCH_KMALLOC_MINALIGN,
};

void init_sloba_lists(struct sloba_lists *lists)
{
        struct cache_array *heads = (struct cache_array *)lists;
        int i;
        for(i = 0;i < NUM_OF_SLOBA_LISTS;i++, heads++){
                heads->head = NULL;
                heads->size = cache_sizes[i];
        }
}

void __init kmem_cache_init(void)
{
        unsigned int cpu;
	kmem_cache = &kmem_cache_boot;
	
        for_each_possible_cpu(cpu){
                struct sloba_lists *lists = &per_cpu(sloba_slabs, cpu);
                init_sloba_lists(lists);
        }

	slab_state = UP;
}

void __init kmem_cache_init_late(void)
{
	slab_state = FULL;
}
