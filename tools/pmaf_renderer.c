#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define M1 UINT64_C(0xbf58476d1ce4e5b9)
#define M2 UINT64_C(0x94d049bb133111eb)
#define GOLD UINT64_C(0x9e3779b97f4a7c15)
#define K UINT64_C(0xd6e8feb86659fd93)
#define K2 UINT64_C(0x243f6a8885a308d3)
#define K3 UINT64_C(0x6f3d9b21a4c875e1)
#define RANDOM_SENTINEL UINT32_C(0x00f2eadf)
#define MARK UINT32_C(0x01000000)

typedef struct {
    int32_t u;
    int32_t v;
    int32_t next_u;
    int32_t prev_u;
    int32_t next_v;
    int32_t prev_v;
} Edge;

typedef struct {
    int32_t *parent;
    int32_t *size;
    uint32_t *color;
    uint64_t *digest;
    int32_t *head;
    int32_t *seen;
    int32_t *matches;
    Edge *edges;
    uint32_t width;
    uint32_t height;
    int32_t edge_count;
    int32_t match_generation;
} Renderer;

typedef struct {
    uint32_t count;
    uint32_t old_color;
    uint64_t digest;
} FillResult;

static inline uint64_t mix64(uint64_t x) {
    x = (x ^ (x >> 30)) * M1;
    x = (x ^ (x >> 27)) * M2;
    return x ^ (x >> 31);
}

static inline uint64_t pre_mix64(uint64_t x) {
    x = (x ^ (x >> 30)) * M1;
    return (x ^ (x >> 27)) * M2;
}

static inline int32_t find_root(Renderer *r, int32_t x) {
    int32_t root = x;
    while (r->parent[root] != root)
        root = r->parent[root];
    while (r->parent[x] != x) {
        int32_t next = r->parent[x];
        r->parent[x] = root;
        x = next;
    }
    return root;
}

static inline int32_t union_initial(Renderer *r, int32_t a, int32_t b) {
    a = find_root(r, a);
    b = find_root(r, b);
    if (a == b)
        return a;
    if (r->size[a] < r->size[b]) {
        int32_t t = a;
        a = b;
        b = t;
    }
    r->parent[b] = a;
    r->size[a] += r->size[b];
    r->digest[a] ^= r->digest[b];
    return a;
}

static inline int32_t edge_next(const Edge *e, int side) {
    return side == 0 ? e->next_u : e->next_v;
}

static inline int32_t edge_prev(const Edge *e, int side) {
    return side == 0 ? e->prev_u : e->prev_v;
}

static inline void set_edge_next(Edge *e, int side, int32_t x) {
    if (side == 0)
        e->next_u = x;
    else
        e->next_v = x;
}

static inline void set_edge_prev(Edge *e, int side, int32_t x) {
    if (side == 0)
        e->prev_u = x;
    else
        e->prev_v = x;
}

static inline int edge_side(const Edge *e, int32_t root) {
    return e->u == root ? 0 : 1;
}

static inline int32_t edge_endpoint(const Edge *e, int side) {
    return side == 0 ? e->u : e->v;
}

static inline void set_edge_endpoint(Edge *e, int side, int32_t root) {
    if (side == 0)
        e->u = root;
    else
        e->v = root;
}

static void unlink_edge(Renderer *r, int32_t edge_id, int side, int32_t root) {
    Edge *e = &r->edges[edge_id];
    int32_t prev = edge_prev(e, side);
    int32_t next = edge_next(e, side);
    if (prev < 0) {
        r->head[root] = next;
    } else {
        int prev_side = edge_side(&r->edges[prev], root);
        set_edge_next(&r->edges[prev], prev_side, next);
    }
    if (next >= 0) {
        int next_side = edge_side(&r->edges[next], root);
        set_edge_prev(&r->edges[next], next_side, prev);
    }
    set_edge_next(e, side, -1);
    set_edge_prev(e, side, -1);
}

static void link_edge(Renderer *r, int32_t edge_id, int side, int32_t root) {
    Edge *e = &r->edges[edge_id];
    int32_t old_head = r->head[root];
    set_edge_prev(e, side, -1);
    set_edge_next(e, side, old_head);
    if (old_head >= 0) {
        int old_side = edge_side(&r->edges[old_head], root);
        set_edge_prev(&r->edges[old_head], old_side, edge_id);
    }
    r->head[root] = edge_id;
}

static inline void add_edge(Renderer *r, int32_t a, int32_t b) {
    a = find_root(r, a);
    b = find_root(r, b);
    if (a == b)
        return;
    int32_t id = r->edge_count++;
    Edge *e = &r->edges[id];
    e->u = a;
    e->v = b;
    e->next_u = e->prev_u = -1;
    e->next_v = e->prev_v = -1;
    link_edge(r, id, 0, a);
    link_edge(r, id, 1, b);
}

static int32_t union_components(Renderer *r, int32_t a, int32_t b) {
    a = find_root(r, a);
    b = find_root(r, b);
    if (a == b)
        return a;
    if (r->size[a] < r->size[b]) {
        int32_t t = a;
        a = b;
        b = t;
    }
    int32_t big = a;
    int32_t small = b;
    int32_t edge_id = r->head[small];
    while (edge_id >= 0) {
        Edge *e = &r->edges[edge_id];
        int side_small = edge_side(e, small);
        int32_t next_small = edge_next(e, side_small);
        int32_t other = edge_endpoint(e, 1 - side_small);
        other = find_root(r, other);
        unlink_edge(r, edge_id, side_small, small);
        if (other == big) {
            int side_big = edge_side(e, big);
            unlink_edge(r, edge_id, side_big, big);
            e->u = -1;
            e->v = -1;
        } else {
            set_edge_endpoint(e, side_small, big);
            link_edge(r, edge_id, side_small, big);
        }
        edge_id = next_small;
    }
    r->head[small] = -1;
    r->parent[small] = big;
    r->size[big] += r->size[small];
    r->digest[big] ^= r->digest[small];
    return big;
}

static inline uint64_t read_le64(const uint8_t *p) {
    return (uint64_t)p[0] |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static inline FillResult paint(Renderer *r, int32_t index, uint32_t requested) {
    int32_t root = find_root(r, index);
    uint32_t old_color = r->color[root];
    uint32_t target = old_color == requested ? old_color | MARK : requested;
    FillResult result = {(uint32_t)r->size[root], old_color, r->digest[root]};
    r->color[root] = target;

    int32_t generation = ++r->match_generation;
    int32_t match_count = 0;
    for (int32_t edge_id = r->head[root]; edge_id >= 0;) {
        Edge *e = &r->edges[edge_id];
        int side = edge_side(e, root);
        int32_t next = edge_next(e, side);
        int32_t neighbor = find_root(r, edge_endpoint(e, 1 - side));
        if (neighbor != root && r->color[neighbor] == target &&
            r->seen[neighbor] != generation) {
            r->seen[neighbor] = generation;
            r->matches[match_count++] = neighbor;
        }
        edge_id = next;
    }
    for (int32_t i = 0; i < match_count; ++i) {
        root = find_root(r, root);
        int32_t neighbor = find_root(r, r->matches[i]);
        if (neighbor != root && r->color[neighbor] == target)
            root = union_components(r, root, neighbor);
    }
    return result;
}

static inline uint64_t transition(uint64_t state, uint64_t counter,
                                 uint32_t target, FillResult fill,
                                 uint64_t *pre_state) {
    uint64_t packed = ((uint64_t)fill.old_color << 24) | target;
    uint64_t value = (packed >> 30) ^ packed;
    uint64_t pre_color = ((value * M1) ^ ((value * M1) >> 27)) * M2;
    uint64_t z = state ^ counter ^ ((uint64_t)fill.count * K) ^
                 mix64(fill.digest) ^ pre_color ^ (pre_color >> 31);
    uint64_t pre = pre_mix64(z);
    if (pre_state != NULL)
        *pre_state = pre;
    return pre ^ (pre >> 31);
}

static inline uint32_t random_color(uint64_t counter, uint64_t state,
                                    uint64_t salt) {
    uint64_t value = counter ^ state ^ salt;
    uint64_t candidate = mix64(value);
    uint32_t color = ((uint32_t)candidate & UINT32_C(0x00fffffe)) | 1U;
    while (color == RANDOM_SENTINEL) {
        value = mix64(value + GOLD);
        candidate = mix64(value);
        color = ((uint32_t)candidate & UINT32_C(0x00fffffe)) | 1U;
    }
    return color;
}

static void free_renderer(Renderer *r) {
    free(r->parent);
    free(r->size);
    free(r->color);
    free(r->digest);
    free(r->head);
    free(r->seen);
    free(r->matches);
    free(r->edges);
}

int pmaf_render(uint32_t *pixels, uint32_t width, uint32_t height,
                const uint8_t *stream, uint64_t op_count, uint64_t seed,
                uint32_t mode, uint64_t *bad_op) {
    uint64_t area64 = (uint64_t)width * height;
    if (width == 0 || height == 0 || area64 > UINT32_C(0x00ffffff))
        return 3;
    uint32_t area = (uint32_t)area64;
    uint64_t max_edges64 = (uint64_t)height * (width - 1) +
                           (uint64_t)width * (height - 1);
    if (max_edges64 > INT32_MAX)
        return 3;

    Renderer r = {0};
    r.width = width;
    r.height = height;
    r.parent = (int32_t *)malloc((size_t)area * sizeof(int32_t));
    r.size = (int32_t *)malloc((size_t)area * sizeof(int32_t));
    r.color = (uint32_t *)malloc((size_t)area * sizeof(uint32_t));
    r.digest = (uint64_t *)malloc((size_t)area * sizeof(uint64_t));
    r.head = (int32_t *)malloc((size_t)area * sizeof(int32_t));
    r.seen = (int32_t *)calloc((size_t)area, sizeof(int32_t));
    r.matches = (int32_t *)malloc((size_t)area * sizeof(int32_t));
    r.edges = (Edge *)malloc((size_t)max_edges64 * sizeof(Edge));
    if (!r.parent || !r.size || !r.color || !r.digest || !r.head ||
        !r.seen || !r.matches || (max_edges64 != 0 && !r.edges)) {
        free_renderer(&r);
        return 4;
    }

    for (uint32_t i = 0; i < area; ++i) {
        r.parent[i] = (int32_t)i;
        r.size[i] = 1;
        r.color[i] = pixels[i] & UINT32_C(0x00ffffff);
        r.digest[i] = mix64((uint64_t)i ^ K2);
        r.head[i] = -1;
    }

    for (uint32_t y = 0; y < height; ++y) {
        uint32_t row = y * width;
        for (uint32_t x = 0; x < width; ++x) {
            uint32_t i = row + x;
            if (x + 1 < width && r.color[i] == r.color[i + 1])
                union_initial(&r, (int32_t)i, (int32_t)(i + 1));
            if (y + 1 < height && r.color[i] == r.color[i + width])
                union_initial(&r, (int32_t)i, (int32_t)(i + width));
        }
    }

    for (uint32_t y = 0; y < height; ++y) {
        uint32_t row = y * width;
        for (uint32_t x = 0; x < width; ++x) {
            uint32_t i = row + x;
            if (x + 1 < width)
                add_edge(&r, (int32_t)i, (int32_t)(i + 1));
            if (y + 1 < height)
                add_edge(&r, (int32_t)i, (int32_t)(i + width));
        }
    }

    uint64_t count_pre = pre_mix64(op_count);
    uint64_t state = mix64((count_pre >> 31) ^ seed ^ height ^
                           ((uint64_t)width << 32) ^
                           ((uint64_t)mode * K) ^ count_pre ^ K3);
    int status = 0;
    for (uint64_t k = 0; k < op_count; ++k) {
        uint64_t counter = k * GOLD;
        uint64_t decoded = read_le64(stream + (size_t)k * 8) ^
                           mix64(counter ^ state);
        uint32_t index = (uint32_t)(decoded & UINT32_C(0x00ffffff));
        uint32_t color = (uint32_t)((decoded >> 24) & UINT32_C(0x00ffffff));
        uint32_t check = (uint32_t)(decoded >> 48);
        uint64_t check_input = (((uint64_t)color << 24) | index) ^
                               (counter ^ state);
        if (index >= area || (uint32_t)(mix64(check_input) >> 48) != check) {
            if (bad_op != NULL)
                *bad_op = k;
            status = index >= area ? 2 : 1;
            break;
        }

        FillResult main_fill = paint(&r, (int32_t)index, color);
        state = transition(state, counter, color, main_fill, NULL);

        if (mode != 0) {
            uint64_t salt = K;
            for (uint32_t round = 0; round < mode; ++round) {
                uint32_t random = random_color(counter, state, salt);
                FillResult random_fill = paint(&r, (int32_t)index, random);
                uint64_t state_after_random = transition(
                    state, counter, random, random_fill, NULL);

                FillResult restore_fill = paint(&r, (int32_t)index, color);
                uint64_t packed = ((uint64_t)restore_fill.old_color << 24) | color;
                uint64_t value = (packed >> 30) ^ packed;
                uint64_t pre_color = ((value * M1) ^ ((value * M1) >> 27)) * M2;
                uint64_t z = state_after_random ^ counter ^
                    ((uint64_t)restore_fill.count * K) ^
                    mix64(restore_fill.digest) ^ pre_color ^
                    (pre_color >> 31);
                state = mix64(z);
                salt += K;
            }
        }
    }

    if (status == 0) {
        for (uint32_t i = 0; i < area; ++i) {
            int32_t root = find_root(&r, (int32_t)i);
            pixels[i] = r.color[root] & UINT32_C(0x00ffffff);
        }
    }
    free_renderer(&r);
    return status;
}
