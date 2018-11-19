// SPDX-License-Identifier: GPL-2.0
/*
 * SLOBA Allocator: Stacking List Oriented Basic Architecture Allocator
 *
 * Akihiro Takai <at.sisy@gmail.com>
 *
 * Some functions defined in SLOB are used in SLOBA Allocator. Thanks a lot!!
 * 
 * Matt Mackall <mpm@selenic.com> 12/30/03
 *
 * NUMA support by Paul Mundt, 2007.
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

#define KMALLOC_ALLOCATE 1
#define KMEM_CACHE_ALLOCATE 0
#define NUM_OF_SLOBA_LISTS 45

#define PAGE_HEAD_INFO_RCU (0x01)
#define PAGE_HEAD_INFO_RELEASE_SOON (0x02)

struct page_cache_head {
	void *freelist;
	unsigned short avail; // available objects
	unsigned short counter;
	unsigned short size;
        unsigned char flags;
        unsigned char smash_check; // this field must be set 0x1a
};

static inline void dump_page_cache_head(struct page_cache_head *page_head)
{
	printk(KERN_ERR
	       "freelist: 0x%llx\navail: %d\ncounter: %d\nsize: %d\nsmash_check: 0x%x",
	       (u64)page_head->freelist, page_head->avail, page_head->counter,
	       page_head->size, page_head->smash_check);
}

static inline void page_cache_set_smash_check(struct page_cache_head *page_head)
{
        page_head->smash_check = 0x1a;
}

static inline char page_cache_is_smashed(struct page_cache_head *page_head)
{
        return page_head->smash_check != 0x1a;
}

#define AVAILABLE_PER_PAGE (PAGE_SIZE - sizeof(struct page_cache_head))
#define GO_BUDDY_SYSTEM (AVAILABLE_PER_PAGE >> 1)

struct sloba_lists {
	struct kmem_cache bins[NUM_OF_SLOBA_LISTS];
};

DEFINE_PER_CPU(struct sloba_lists, sloba_slabs);

static unsigned short cache_sizes[] = {
	0,   8,   16,   24,   32,   40,   48,   56,   64,   72,  80,  88,
	96,  104, 112,  120,  128,  144,  160,  176,  192,  208, 224, 240,
	256, 288, 320,  352,  384,  416,  448,  480,  512,  576, 640, 704,
	768, 896, 1024, 1536, 2048, 2560, 3072, 4096, 10000
};

/**
 * page_cache_get_head: page_cache_headから、ページの利用可能な領域の先頭のアドレスを返す
 * @p: ページの先頭
 */
static inline void *page_cache_get_head(struct page_cache_head *p)
{
	return (void *)(&p[1]);
}

static inline void *get_page_end(struct page_cache_head *p)
{
	return (void *)(((void *)p) + PAGE_SIZE);
}

static inline void *sloba_get_object(struct page_cache_head *p, short index)
{
	BUG_ON(index < 0);
	return (void *)(get_page_end(p) -
			(unsigned long long)(p->size * index));
}

static int bins_index(size_t size)
{
	if (size <= 8)
		return 1;
	if (size <= 16)
		return 2;
	if (size <= 24)
		return 3;
	if (size <= 32)
		return 4;
	if (size <= 40)
		return 5;
	if (size <= 48)
		return 6;
	if (size <= 56)
		return 7;
	if (size <= 64)
		return 8;
	if (size <= 72)
		return 9;
	if (size <= 80)
		return 10;
	if (size <= 88)
		return 11;
	if (size <= 96)
		return 12;
	if (size <= 104)
		return 13;
	if (size <= 112)
		return 14;
	if (size <= 120)
		return 15;
	if (size <= 128)
		return 16;
	if (size <= 144)
		return 17;
	if (size <= 160)
		return 18;
	if (size <= 176)
		return 19;
	if (size <= 192)
		return 20;
	if (size <= 208)
		return 21;
	if (size <= 224)
		return 22;
	if (size <= 240)
		return 23;
	if (size <= 256)
		return 24;
	if (size <= 288)
		return 25;
	if (size <= 320)
		return 26;
	if (size <= 352)
		return 27;
	if (size <= 384)
		return 28;
	if (size <= 416)
		return 29;
	if (size <= 448)
		return 30;
	if (size <= 480)
		return 31;
	if (size <= 512)
		return 32;
	if (size <= 576)
		return 33;
	if (size <= 640)
		return 34;
	if (size <= 704)
		return 35;
	if (size <= 768)
		return 36;
	if (size <= 896)
		return 37;
	if (size <= 1024)
		return 38;
	if (size <= 1536)
		return 39;
	if (size <= 2048)
		return 40;
	if (size <= 2560)
		return 41;
	if (size <= 3072)
		return 42;
	if (size <= 4096)
		return 43;
	return 44;
}

#define sloba_push_stack_list(list_head, new_elem)                             \
	({                                                                     \
		*(void **)(new_elem) = (list_head);                            \
		(list_head) = (new_elem);                                      \
	})

#define sloba_pop_stack_list(list_head)                                        \
	({ (list_head) = *(void **)(list_head); })

static inline char is_cache_array_for_kmalloc(struct cache_array *c_array)
{
	return c_array->flags & CACHE_ARRAY_KMALLOC;
}

/**
 * mark_non_reusable_flag: mark non_reusable flag
 * @page_head: This page will be marked
 */
static inline void mark_non_reusable_flag(struct page_cache_head *page_head)
{
        page_head->flags |= PAGE_HEAD_INFO_RCU;
}

/**
 * is_non_reusable_page: To check the page is filled and destroyed
 * @page_head: The head of page
 */
static inline char is_non_reusable_page(struct page_cache_head *page_head)
{
	return page_head->flags & PAGE_HEAD_INFO_RCU;
}

/**
 * get_proper_sloba_list: 要求されたサイズにあったcache_arrayを返す
 * @size: 要求するサイズ
 */
static struct kmem_cache *get_proper_sloba_list(size_t size)
{
	struct sloba_lists *sloba_lists;
	int index = bins_index(size);
	sloba_lists = &per_cpu(sloba_slabs, smp_processor_id());
	return (((struct kmem_cache *)sloba_lists) + index);
}

static inline void clear_sloba_page_cache(struct page *sp)
{
	sp->slab_cache = NULL;
}

/**
 * page_head_init: ページを初期化する関数
 * @head: page_cache_head構造体
 * @cache_size: キャッシュのサイズ
 */
static inline void page_head_init(struct page_cache_head *head, struct kmem_cache *cachep)
{
	virt_to_page(head)->slab_cache = cachep;

	head->freelist = NULL;
        head->size = cachep->c_array.size;
	head->avail = (AVAILABLE_PER_PAGE / cachep->c_array.size);
	head->counter = 0;
        head->flags = 0;
        page_cache_set_smash_check(head);

	if (cachep->flags & SLAB_TYPESAFE_BY_RCU) {
		mark_non_reusable_flag(head);
	}
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

static void slob_free_pages(void *b, int order)
{
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += 1 << order;
	free_pages((unsigned long)b, order);
}

static void sloba_finalize_page(struct kmem_cache *cachep, struct page *sp)
{
        /*
         * This is STUB
         */
}

/**
 * sloba_alloc_from_freelist: To alloc object space from freelist
 * @page_head: The freelist in this page will be refered to allocate space
 * @size: required size
 */
static void *sloba_alloc_from_freelist(struct page_cache_head *page_head)
{
        void *ret = NULL;

	// available space is found in freelist
	if (page_head->freelist) {
		ret = page_head->freelist;
		sloba_pop_stack_list(page_head->freelist);
	}
        
	return ret;
}

/**
 * cache_array_init_firstpage: cache_arrayを初期化する関数
 * @ca: 初期化するcache_array構造体
 * @gfp: gfp
 * @node: node
 */
static void *cache_array_init_firstpage(struct kmem_cache *cachep,
					struct cache_array *ca, gfp_t gfp,
					int node)
{
	unsigned long flags;
        void *ret;
        
	// allocate new page
        ret = slob_new_pages(gfp & ~__GFP_ZERO, 0, node);
        if (!ret)
		return NULL;
        
        spin_lock_irqsave(&slob_lock, flags);

        ca->head = ret;
	// if buddy system failed to allocate new page, return NULL
        
	page_head_init(ca->head, cachep);
        
	__SetPageSlab(virt_to_page(ca->head));

        spin_unlock_irqrestore(&slob_lock, flags);
	return ca->head;
}

/**
 * sloba_alloc_new_page: To allocate new page
 * @page_head: Old page, This page will be marked non_reusable flag
 * @gfp: To use get new page
 */
static void *sloba_alloc_new_page(struct kmem_cache *cachep,
				  struct cache_array *c_array, gfp_t gfp,
				  int node)
{
	struct page_cache_head *ret;
	struct page *ret_sp;
        unsigned long flags;
        
	ret = slob_new_pages(gfp, get_order(c_array->size), node);

        spin_lock_irqsave(&slob_lock, flags);

        ((struct page_cache_head *)(c_array->head))->flags |= PAGE_HEAD_INFO_RELEASE_SOON;

        ret_sp = virt_to_page(ret);
	c_array->head = ret;
        page_head_init(ret, cachep);
	__SetPageSlab(ret_sp);

        spin_unlock_irqrestore(&slob_lock, flags);

	return ret;
}

static void sloba_pre_free_pages(void *page_head)
{        
        struct page *sp;

        sp = virt_to_page(page_head);
        sp->mapping = NULL;

        __ClearPageSlab(sp);
        page_mapcount_reset(sp);
}

/**
 * sloba_alloc: The core process of allocating memory
 * @sloba_cache: The memory space this function will return is allocated from this argument
 * @size: size of object
 * @gfp: gfp options
 * @node: node
 */
static void *sloba_alloc(struct kmem_cache *cachep, size_t size, gfp_t gfp,
			 int node)
{
	void *b = NULL;
	unsigned long flags;
	struct page_cache_head *page_head;
	struct cache_array *sloba_cache = &cachep->c_array;

	/*
         * this cache_array is not initialized
         */
	if (!sloba_cache->head &&
	    !cache_array_init_firstpage(cachep, sloba_cache, gfp, node))
		return NULL;

        spin_lock_irqsave(&slob_lock, flags);
        
	// we'll allocate slab from this page
	page_head = sloba_cache->head;

	if ((b = sloba_alloc_from_freelist(page_head))) {
		goto done;
	}

	// if this page is not available, find available page
	if (!page_head->avail){
                spin_unlock_irqrestore(&slob_lock, flags);
		page_head = sloba_alloc_new_page(cachep, sloba_cache, gfp & ~__GFP_ZERO, node);
                spin_lock_irqsave(&slob_lock, flags);
        }

	// get slab from back
	b = (void *)(((unsigned long long)page_head) +
                     ((unsigned long long)PAGE_SIZE - (unsigned long long)(page_head->size * (page_head->avail--))));
done:
	page_head->counter++;
        spin_unlock_irqrestore(&slob_lock, flags);

	if (unlikely(gfp & __GFP_ZERO))
		memset(b, 0, size);

        BUG_ON(page_cache_is_smashed(page_head));

	return b;
}

static void kmem_rcu_free(struct rcu_head *head)
{
	struct page *page;
        size_t size;
        void *page_head;
        int order;

	page = container_of(head, struct page, rcu_head);
        size = page->slab_cache->c_array.size;
        order = get_order(size);
        page_head = page_address(page);

        if(likely(PageSlab(page))){
                sloba_pre_free_pages(page_head);
        }else{
                page->slab_cache = NULL;
        }
        slob_free_pages(page_head, order);
}

/**
 * sloba_free: The core process of freeing memory
 * @block: The head address of freeing memory space
 * @size: size of memory space
 */
static void sloba_free(void *block, int size)
{
	struct page_cache_head *page_head;
	unsigned long flags;

	if (unlikely(ZERO_OR_NULL_PTR(block)))
		return;
	BUG_ON(!size);

        spin_lock_irqsave(&slob_lock, flags);

	page_head =
		(struct page_cache_head *)((unsigned long)block & PAGE_MASK);
	page_head->counter--;

        if(unlikely((page_head->flags & PAGE_HEAD_INFO_RELEASE_SOON) && !page_head->counter)){
                if (is_non_reusable_page(page_head)) {
                        spin_unlock_irqrestore(&slob_lock, flags);
			call_rcu(&virt_to_page(page_head)->rcu_head, kmem_rcu_free);
		} else {
                        spin_unlock_irqrestore(&slob_lock, flags);
                        sloba_pre_free_pages(page_head);
                        slob_free_pages(page_head, 0);
		}
                return;
	} else {
		if (!is_non_reusable_page(page_head)) {
			sloba_push_stack_list(page_head->freelist, block);
		}
	}

        spin_unlock_irqrestore(&slob_lock, flags);
}

/*
 * End of slob allocator proper. Begin kmem_cache_alloc and kmalloc frontend.
 */
static __always_inline void *__do_kmalloc_node(size_t size, gfp_t gfp, int node,
					       unsigned long caller)
{
	void *ret;

	gfp &= gfp_allowed_mask;

	fs_reclaim_acquire(gfp);
	fs_reclaim_release(gfp);

	if (size < GO_BUDDY_SYSTEM) {
                struct kmem_cache *cachep = get_proper_sloba_list(size);
		if (!size)
			return ZERO_SIZE_PTR;

		ret = sloba_alloc(cachep, size, gfp, node);

		if (!ret)
			return NULL;

		trace_kmalloc_node(caller, ret, size, cachep->size, gfp, node);
	} else {
		unsigned int order = get_order(size);

		if (likely(order))
			gfp |= __GFP_COMP;
		ret = slob_new_pages(gfp, order, node);
		trace_kmalloc_node(caller, ret, size, PAGE_SIZE << order, gfp,
				   node);
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
void *__kmalloc_node_track_caller(size_t size, gfp_t gfp, int node,
				  unsigned long caller)
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
	if (likely(PageSlab(sp))) {
                size_t size = ksize(block);
                sloba_free(block, size);
	} else {
                __free_pages(sp, compound_order(sp));
        }
}
EXPORT_SYMBOL(kfree);

/* can't use ksize for kmem_cache_alloc memory, only kmalloc */
size_t ksize(const void *block)
{
	struct page *sp;

	BUG_ON(!block);
	if (unlikely(block == ZERO_SIZE_PTR))
		return 0;

	sp = virt_to_page(block);
	if (unlikely(!PageSlab(sp)))
		return PAGE_SIZE << compound_order(sp);

	return sp->slab_cache->size;
}
EXPORT_SYMBOL(ksize);

int __kmem_cache_create(struct kmem_cache *c, slab_flags_t flags)
{
	c->c_array.head = NULL;
	c->c_array.size = ALIGN(c->size, c->align);
	c->c_array.flags = 0;
	c->flags = flags;

	return 0;
}

static void *sloba_alloc_large_object(struct kmem_cache *c, gfp_t gfp, int node)
{
	void *ret;
        unsigned long flags;
        unsigned int order = get_order(c->c_array.size);
        
        if (likely(order))
                gfp |= __GFP_COMP;
        ret = slob_new_pages(gfp & ~__GFP_ZERO, order, node);

        virt_to_page(ret)->slab_cache = c;

	if (unlikely(gfp & __GFP_ZERO))
		memset(ret, 0, c->size);

	return ret;
}

static void sloba_free_large_object(struct kmem_cache *c, void *b,
				    int size)
{
        struct page *sp = virt_to_page(b);

	if (unlikely(c->flags & SLAB_TYPESAFE_BY_RCU)) {
		call_rcu(&sp->rcu_head, kmem_rcu_free);
	} else {
                sp->slab_cache = NULL;
                slob_free_pages(page_address(sp), get_order(size));
	}
}

static void *slob_alloc_node(struct kmem_cache *c, gfp_t flags, int node)
{
	void *b;

	flags &= gfp_allowed_mask;

	fs_reclaim_acquire(flags);
	fs_reclaim_release(flags);

	if (c->c_array.size < GO_BUDDY_SYSTEM) {
		if (!c->size)
			return ZERO_SIZE_PTR;
		b = sloba_alloc(c, c->size, flags, node);
		trace_kmem_cache_alloc_node(_RET_IP_, b, c->object_size,
					    c->c_array.size, flags, node);
	} else {
		b = slob_new_pages(flags, get_order(c->size), node);
                virt_to_page(b)->slab_cache = c;
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

static void __kmem_cache_free(struct kmem_cache *cachep, void *b, int size)
{
        struct page *sp = virt_to_page(b);
        
	if (likely(PageSlab(sp))) {
		sloba_free(b, size);
	} else {
		sloba_free_large_object(cachep, b, size);
	}
}

void kmem_cache_free(struct kmem_cache *c, void *b)
{
	kmemleak_free_recursive(b, c->flags);
	__kmem_cache_free(c, b, c->size);
	trace_kmem_cache_free(_RET_IP_, b);
}
EXPORT_SYMBOL(kmem_cache_free);

void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
{
	__kmem_cache_free_bulk(s, size, p);
}
EXPORT_SYMBOL(kmem_cache_free_bulk);

int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
			  void **p)
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

int __kmem_cache_shrink(struct kmem_cache *c)
{
	return 0;
}

struct kmem_cache kmem_cache_boot = {
	.name = "kmem_cache",
	.size = sizeof(struct kmem_cache),
	.flags = SLAB_PANIC,
	.align = ARCH_KMALLOC_MINALIGN,
        .c_array = {
                .head = NULL,
                .size = ALIGN(sizeof(struct kmem_cache), ARCH_KMALLOC_MINALIGN),
                .flags = 0,
        },
};

/**
 * init_sloba_lists: slobaのcache_arrayに初期値を入れておく関数
 * @lists: cache_arrayのリスト
 */
void init_sloba_lists(struct sloba_lists *lists)
{
	struct kmem_cache *heads = (struct kmem_cache *)lists;
	int i;
	for (i = 0; i < NUM_OF_SLOBA_LISTS; i++, heads++) {
		heads->c_array.head = NULL;
                heads->size = cache_sizes[i];
                heads->object_size = heads->size;
                heads->c_array.size = heads->size;
		heads->c_array.flags = CACHE_ARRAY_KMALLOC;
                heads->flags = 0;
	}
}

void __init kmem_cache_init(void)
{
	unsigned int cpu;
	kmem_cache = &kmem_cache_boot;
        
	for_each_possible_cpu (cpu) {
		struct sloba_lists *lists = &per_cpu(sloba_slabs, cpu);
		init_sloba_lists(lists);
	}
        
	slab_state = UP;
}

void __init kmem_cache_init_late(void)
{
	slab_state = FULL;
}
