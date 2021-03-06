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

#define SLOBA_PAGE_SIZE (PAGE_SIZE << 2)
#define SLOBA_PAGE_ORDER (get_order(SLOBA_PAGE_SIZE))

struct page_cache_head {
	void *freelist;
	unsigned short avail; // available objects
	unsigned short counter;
	unsigned short size; // 
        unsigned char flags; // status of the page
        unsigned char smash_check; // this field must be set 0x1a
};

/**
 * @dump_page_cache_head
 * Dump page_cache_head
 * @page_head A pointer to the instance of page_cache_head you want to dump
 */
static inline void dump_page_cache_head(struct page_cache_head *page_head)
{
	printk(KERN_ERR
	       "freelist: 0x%llx\navail: %d\ncounter: %d\nsize: %d\nsmash_check: 0x%x",
	       (u64)page_head->freelist, page_head->avail, page_head->counter,
	       page_head->size, page_head->smash_check);
}

/**
 * @page_cache_set_smash_check
 * initialize smash_check in page_head as 0x1a
 * @page_head target structure
 */
static inline void page_cache_set_smash_check(struct page_cache_head *page_head)
{
        page_head->smash_check = 0x1a;
}

/**
 * @page_cache_is_smashed
 * Check the page_cache_head is smashed
 * @page_head target structure
 */
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
 * @page_cache_get_head
 * page_cache_headから、ページの利用可能な領域の先頭のアドレスを返す
 * @p ページの先頭
 */
static inline void *page_cache_get_head(struct page_cache_head *p)
{
	return (void *)(&p[1]);
}

/**
 * @bins_index
 * get index of kmem_cache for kmalloc
 * @size required size
 */
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

/**
 * @def
 * push address to stacking list
 */
#define sloba_push_stack_list(list_head, new_elem)                             \
	({                                                                     \
		*(void **)(new_elem) = (list_head);                            \
		(list_head) = (new_elem);                                      \
	})

/**
 * @def
 * pop address from stacking list
 */
#define sloba_pop_stack_list(list_head)                                        \
	({ (list_head) = *(void **)(list_head); })

static inline char is_cache_array_for_kmalloc(struct cache_array *c_array)
{
	return c_array->flags & CACHE_ARRAY_KMALLOC;
}

/**
 * @mark_non_reusable_flag
 * set non_reusable flag
 * @page_head: A pointer point to insstance of page_cache_head
 */
static inline void mark_non_reusable_flag(struct page_cache_head *page_head)
{
        page_head->flags |= PAGE_HEAD_INFO_RCU;
}

/**
 * @is_non_reusable_page
 * Check the page is non-reusable
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
 * @page_head_init
 * initialize a instance of page_cache_head
 * @head: page_cache_head構造体
 * @cache_size: size of cache
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

/**
 * @alloc_pages_from_buddy
 * allocate pages from buddy system
 * @gfp gfp flag
 * @order order of page size
 * @node node
 */
static void *alloc_pages_from_buddy(gfp_t gfp, int order, int node)
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

/**
 * @free_slab_pages
 * free slab pages
 * @b address of head of page
 * @order order of freeing pages's size
 */
static void free_slab_pages(void *b, int order)
{
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += 1 << order;
	free_pages((unsigned long)b, order);
}

/**
 * @sloba_alloc_from_freelist
 * allocate object space from freelist
 * @page_head The freelist in this page will be refered to allocate space
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
 * @cache_array_init_firstpage
 * Initialize cache_array object
 * @c_array cache_array object
 * @gfp gfp flag
 * @node node
 */
static void *cache_array_init_firstpage(struct kmem_cache *cachep,
					struct cache_array *c_array, gfp_t gfp,
					int node)
{
	unsigned long flags;
        void *ret;
        
	// allocate new page
        ret = alloc_pages_from_buddy(gfp & ~__GFP_ZERO, 0, node);
        if (!ret)
		return NULL;
        
        spin_lock_irqsave(&slob_lock, flags);

        c_array->head = ret;
	// if buddy system failed to allocate new page, return NULL
        
	page_head_init(c_array->head, cachep);
        
	__SetPageSlab(virt_to_page(c_array->head));

        spin_unlock_irqrestore(&slob_lock, flags);
	return c_array->head;
}

/**
 * @sloba_alloc_new_page
 * allocate new sloba pages
 * @cachep kmem_cache object
 * @c_array cache_array object including old pages
 * @gfp gfp flag
 * @node node
 */
static void *sloba_alloc_new_page(struct kmem_cache *cachep,
				  struct cache_array *c_array, gfp_t gfp,
				  int node)
{
	struct page_cache_head *ret;
	struct page *ret_sp;
        unsigned long flags;
        
	ret = alloc_pages_from_buddy(gfp, cachep->order, node);

        spin_lock_irqsave(&slob_lock, flags);

        ((struct page_cache_head *)(c_array->head))->flags |= PAGE_HEAD_INFO_RELEASE_SOON;

        ret_sp = virt_to_page(ret);
	c_array->head = ret;
        page_head_init(ret, cachep);
	__SetPageSlab(ret_sp);

        spin_unlock_irqrestore(&slob_lock, flags);

	return ret;
}

/**
 * @sloba_pre_free_pages
 * some operations for freeing pages
 * @page_head address of page that will be free
 */
static void sloba_pre_free_pages(void *page_head)
{
        struct page *sp;

        sp = virt_to_page(page_head);
        sp->mapping = NULL;

        __ClearPageSlab(sp);
        page_mapcount_reset(sp);
}

/**
 * @sloba_alloc
 * The core process for allocating memory
 * @cachep kmem_cache object
 * @size: real size of slab object (minist) not aligned
 * @gfp: gfp flag
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

/**
 * @kmem_rcu_free
 * a handle of call_rcu
 * @head a pointer point to rcu_head object. This has belonged to "struct page".
 */
static void kmem_rcu_free(struct rcu_head *head)
{
	struct page *page;
        void *page_head;
        int order;

	page = container_of(head, struct page, rcu_head);
        order = page->slab_cache->order;
        page_head = page_address(page);

        sloba_pre_free_pages(page_head);
        __free_pages(page, order);
}

/**
 * @sloba_free
 * The core process for freeing pages
 * @block The address of freeing memory space
 * @size Actual size of allocated memory
 */
static void sloba_free(void *block, int size)
{
	struct page_cache_head *page_head;
	unsigned long flags;

	if (unlikely(ZERO_OR_NULL_PTR(block)))
		return;
	BUG_ON(!size);

	page_head =
		(struct page_cache_head *)((unsigned long)block & PAGE_MASK);

        spin_lock_irqsave(&slob_lock, flags);
	page_head->counter--;

        if(unlikely((page_head->flags & PAGE_HEAD_INFO_RELEASE_SOON) && !page_head->counter)){
                if (is_non_reusable_page(page_head)) {
                        spin_unlock_irqrestore(&slob_lock, flags);
			call_rcu(&virt_to_page(page_head)->rcu_head, kmem_rcu_free);
		} else {
                        spin_unlock_irqrestore(&slob_lock, flags);
                        sloba_pre_free_pages(page_head);
                        free_slab_pages(page_head, 0);
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
		ret = alloc_pages_from_buddy(gfp, order, node);
		trace_kmalloc_node(caller, ret, size, PAGE_SIZE << order, gfp,
				   node);
	}
        
	kmemleak_alloc(ret, size, 1, gfp);

	return ret;
}

/**
 * @__kmalloc
 * Sub function of kmalloc
 * @size required size
 * @gfp gfp flag
 */
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

/**
 * @kfree
 * free previously allocated memory through kmalloc
 * @block address of memory space that will be freed
 */
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
/**
 * @ksize
 * get the actual amount of memory allocated for a given object
 * @block address of a object
 */
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
        c->order = get_order(c->c_array.size);

	return 0;
}

/**
 * @sloba_alloc_large_object
 * allocate an object that larger than size of GO_BUDDY_SYSTEM
 * @c kmem_cache object
 * @gfp gfp flag
 * @node node
 */
static void *sloba_alloc_large_object(struct kmem_cache *c, gfp_t gfp, int node)
{
	void *ret;
        
        if (likely(c->order))
                gfp |= __GFP_COMP;
        ret = alloc_pages_from_buddy(gfp & ~__GFP_ZERO, c->order, node);

        virt_to_page(ret)->slab_cache = c;

	if (unlikely(gfp & __GFP_ZERO))
		memset(ret, 0, c->size);

	return ret;
}

/**
 * @sloba_free_large_object
 * free an object that larger than size of GO_BUDDY_SYSTEM
 * @c kmem_cache object
 * @b head address of memory that will be freed
 * @size real size of object (not aligned)
 */
static void sloba_free_large_object(struct kmem_cache *c, void *b,
				    int size)
{
        struct page *sp = virt_to_page(b);

	if (unlikely(c->flags & SLAB_TYPESAFE_BY_RCU)) {
		call_rcu(&sp->rcu_head, kmem_rcu_free);
	} else {
                sp->slab_cache = NULL;
                free_slab_pages(page_address(sp), get_order(size));
	}
}

/**
 * @slob_alloc_node
 * allocate slab object
 * @c The cache to allocate from
 * @flags gfp flag
 * @node node
 */
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
                b = sloba_alloc_large_object(c, flags, node);
		trace_kmem_cache_alloc_node(_RET_IP_, b, c->object_size,
					    PAGE_SIZE << c->order,
					    flags, node);
	}
        
	if (b && c->ctor)
		c->ctor(b);

	kmemleak_alloc_recursive(b, c->size, 1, c->flags, flags);
	return b;
}

/**
 * @kmem_cache_alloc
 * Allocate a slab object
 * @cachep The cache allocate from
 * @flags gdp flags
 */
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

/**
 * @__kmem_cache_free
 * A sub function of kmem_cache_free
 * @cachep kmem_cache object
 * @b address of memory space that will be freed
 * @size size of given slab object
 */
static void __kmem_cache_free(struct kmem_cache *cachep, void *b, int size)
{
        struct page *sp = virt_to_page(b);
        
	if (likely(PageSlab(sp))) {
		sloba_free(b, size);
	} else {
		sloba_free_large_object(cachep, b, size);
	}
}

/**
 * @kmem_cache_free
 * Deallocate an object
 * @cachep kmem_cache object
 * @b address of memory space that will be freed
 */
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
 * @init_sloba_list
 * initialize kmem_cache object for kmalloc
 * @list head address of array of kmem_cache objects
 */
void init_sloba_list(struct sloba_lists *list)
{
	struct kmem_cache *heads = (struct kmem_cache *)list;
	int i;
	for (i = 0; i < NUM_OF_SLOBA_LISTS; i++, heads++) {
		heads->c_array.head = NULL;
                heads->size = cache_sizes[i];
                heads->object_size = heads->size;
                heads->c_array.size = heads->size;
		heads->c_array.flags = CACHE_ARRAY_KMALLOC;
                heads->flags = 0;
                heads->order = 0;
	}
}

/**
 * @kmem_cache_init
 * initialize sloba allocator
 */
void __init kmem_cache_init(void)
{
	unsigned int cpu;
	kmem_cache = &kmem_cache_boot;
        
	for_each_possible_cpu (cpu) {
		struct sloba_lists *lists = &per_cpu(sloba_slabs, cpu);
		init_sloba_list(lists);
	}
        
	slab_state = UP;
}

/**
 * @kmem_cache_init_late
 * Bump up to FULL status
 */
void __init kmem_cache_init_late(void)
{
	slab_state = FULL;
}
