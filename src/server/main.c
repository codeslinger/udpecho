/*
 * DPDK-based UDP echo server
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <endian.h>

#include "dpdk.h"

#define INLINE inline __attribute__((always_inline))
#define UNUSED __attribute__((unused))

#define DIE(msg, ...)                                       \
    do {                                                    \
        RTE_LOG(ERR, USER1, msg , ## __VA_ARGS__ );         \
        exit(EXIT_FAILURE);                                 \
    } while (0)


#define PKT_BURST               32
#define MAX_PKT_BURST           32
#define RX_RING_SIZE            256
#define TX_RING_SIZE            512
#define MEMPOOL_CACHE_SIZE      256
#define MBUF_SIZE               (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MAX_RX_QUEUE_PER_LCORE  16
#define MAX_TX_QUEUE_PER_PORT   RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT   128
#define NUM_SOCKETS             8
#define RX_DESC_DEFAULT         128
#define TX_DESC_DEFAULT         512
#define MAX_LCORE_PARAMS        1024
#define BURST_TX_DRAIN_US       100

/*
 * This expression is used to calculate the number of mbufs needed depending on
 * user input, taking into account memory for rx and tx hardware rings, cache
 * per lcore and mtable per port per lcore. RTE_MAX is used to ensure that
 * NUM_MBUF never goes below a minimum value of 8192.
 */
#define NUM_MBUF(ports, rx, tx, lcores)                 \
    RTE_MAX((ports * rx * RX_DESC_DEFAULT +             \
             ports * lcores * MAX_PKT_BURST +           \
             ports * tx * TX_DESC_DEFAULT +             \
             lcores * MEMPOOL_CACHE_SIZE),              \
            (unsigned) 8192)

struct lcore_params {
    uint8_t port_id;
    uint8_t queue_id;
    uint8_t lcore_id;
} __rte_cache_aligned;

struct mbuf_table {
    uint16_t         len;
    struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_rx_queue {
    uint8_t port_id;
    uint8_t queue_id;
} __rte_cache_aligned;

struct lcore_conf {
    uint16_t                n_rx_queue;
    struct lcore_rx_queue   rx_queues[MAX_RX_QUEUE_PER_LCORE];
    uint16_t                tx_queue_ids[RTE_MAX_ETHPORTS];
    struct mbuf_table       tx_mbufs[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

struct psd_hdr {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t len;
} __attribute__((packed));

static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode        = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .header_split   = 0,
        .hw_ip_checksum = 1,
        .hw_vlan_filter = 0,
        .jumbo_frame    = 1,
        .hw_strip_crc   = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf  = ETH_RSS_IP,
        }
    },
    .txmode = {
    },
};

static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = 8,
        .hthresh = 8,
        .wthresh = 4,
    },
    .rx_free_thresh = 32,
};

/* 
 * XXX: The below tx_thresh values are optimized for Intel 82599 10GigE NICs
 * using the DPDK ixgbe PMD
 */
static const struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = 36,
        .hthresh = 0,
        .wthresh = 0,
    },
    .tx_free_thresh = 0,
    .tx_rs_thresh   = 0,
    .txq_flags      = 0,
};

#define CMD_LINE_OPT_NUMA_ON    "numa"
#define CMD_LINE_OPT_PORTMASK   "portmask"
#define CMD_LINE_OPT_RX_CONFIG  "config"
#define CMD_LINE_OPT_HELP       "help"
static const struct option long_opts[] = {
    {CMD_LINE_OPT_NUMA_ON, 0, 0, 0},
    {CMD_LINE_OPT_PORTMASK, 1, 0, 0},
    {CMD_LINE_OPT_RX_CONFIG, 1, 0, 0},
    {CMD_LINE_OPT_HELP, 0, 0, 0},
    {NULL, 0, 0, 0}
};

static uint32_t              enabled_ports_mask = 0;
static bool                  numa_on = false;
static uint16_t              nb_rxd = RX_DESC_DEFAULT;
static uint16_t              nb_txd = TX_DESC_DEFAULT;
static struct lcore_conf     lcore_conf[RTE_MAX_LCORE];
static struct rte_mempool   *pktmbuf_pool[NUM_SOCKETS];
static struct lcore_params   lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params   lcore_params_array_default[] = {
    {0, 0, 0},
};
static struct lcore_params  *lcore_params = lcore_params_array_default;
static uint16_t              n_lcore_params =
    sizeof(lcore_params_array_default) / sizeof(lcore_params_array_default[0]);

/*
 * Return the CPU socket on which the given logical core resides.
 */
static INLINE uint8_t socket_for_lcore(unsigned lcore_id)
{
    return (numa_on) ? (uint8_t) rte_lcore_to_socket_id(lcore_id) : 0;
}

/*
 * Do incremental addition to one's compliment sum in @start.
 */
static inline uint32_t csum_partial(const uint16_t *p, uint16_t size, uint32_t start)
{
    uint32_t sum = start;

    while (size > 1) {
        sum += *p;
        size -= sizeof(uint16_t);
        p++;
    }
    if (size) {
        sum += *((const uint8_t *) p);
    }
    return sum;
}

/*
 * Fold 32-bit @x one's compliment sum into 16-bit value.
 */
static inline uint16_t csum_fold(uint32_t x)
{
    x = (x & 0x0000FFFF) + (x >> 16);
    x = (x & 0x0000FFFF) + (x >> 16);
    return (uint16_t) x;
}

/*
 * Compute checksum of IPv4 pseudo-header.
 */
static inline uint16_t ipv4_pseudo_csum(struct ipv4_hdr *ip)
{
    struct psd_hdr psd;

    psd.src_addr = ip->src_addr;
    psd.dst_addr = ip->dst_addr;
    psd.zero = 0;
    psd.proto = ip->next_proto_id;
    psd.len = rte_cpu_to_be_16(
        rte_be_to_cpu_16(ip->total_length) - (int)((ip->version_ihl & 0x0F) * 4u));
    return csum_fold(csum_partial((uint16_t *) &psd, sizeof(psd), 0));
}

/*
 * We can't include arpa/inet.h because our compiler options are too strict
 * for that shitty code. Thus, we have to do this here...
 */
static void print_pkt(int src_ip, int dst_ip, uint16_t src_port, uint16_t dst_port, int len)
{
    uint8_t     b[12];
    uint16_t    sp,
                dp;

    b[0] = src_ip & 0xFF;
    b[1] = (src_ip >> 8) & 0xFF;
    b[2] = (src_ip >> 16) & 0xFF;
    b[3] = (src_ip >> 24) & 0xFF;
    b[4] = src_port & 0xFF;
    b[5] = (src_port >> 8) & 0xFF;
    sp = ((b[4] << 8) & 0xFF00) | (b[5] & 0x00FF);
    b[6] = dst_ip & 0xFF;
    b[7] = (dst_ip >> 8) & 0xFF;
    b[8] = (dst_ip >> 16) & 0xFF;
    b[9] = (dst_ip >> 24) & 0xFF;
    b[10] = dst_port & 0xFF;
    b[11] = (dst_port >> 8) & 0xFF;
    dp = ((b[10] << 8) & 0xFF00) | (b[11] & 0x00FF);
    RTE_LOG(DEBUG, USER1,
            "rx: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (%d bytes)\n",
            b[0], b[1], b[2], b[3], sp,
            b[6], b[7], b[8], b[9], dp,
            len);
}

/*
 * Send a number of packets out the specified port (Ethernet device).
 */
static inline int send_burst(struct lcore_conf *conf, uint16_t n, uint8_t port, int socket)
{
    uint16_t          rv,
                      queueid;
    struct rte_mbuf **m_table;

    queueid = conf->tx_queue_ids[port];
    m_table = (struct rte_mbuf **) conf->tx_mbufs[port].m_table;
    rv = rte_eth_tx_burst(port, queueid, m_table, n);
    RTE_LOG(DEBUG, USER1, "rte_eth_tx_burst(port=%u, queue=%u, len=%u) -> %u\n", port, queueid, n, rv);
    if (unlikely(rv < n)) {
        /* drop the packets we couldn't send */
        do { rte_pktmbuf_free(m_table[rv]); } while (++rv < n);
    }
    RTE_LOG(DEBUG, USER1, "free count mempool socket %u: %u\n", socket, rte_mempool_free_count(pktmbuf_pool[socket]));
    return 0;
}

/*
 * Queue a single packet for transmit through a given port (Ethernet device).
 * This will send a burst of packets out if the TX buffer is full.
 */
static inline int send_one(struct lcore_conf *conf, struct rte_mbuf *pkt, uint8_t port, int socket)
{
    uint16_t len;

    len = conf->tx_mbufs[port].len;
    conf->tx_mbufs[port].m_table[len] = pkt;
    len++;
    if (unlikely(len == MAX_PKT_BURST)) {
        send_burst(conf, MAX_PKT_BURST, port, socket);
        len = 0;
    }
    conf->tx_mbufs[port].len = len;
    return 0;
}

/*
 * Echoes back a single UDP packet to its origin.
 */
static INLINE int echo_single_udp_packet(struct rte_mbuf *pkt)
{
    int                l2_len;
    uint16_t           eth_type,
                       udp_port;
    uint32_t           ip_addr;
    struct udp_hdr    *udp_h;
    struct ipv4_hdr   *ip_h;
    struct vlan_hdr   *vlan_h;
    struct ether_hdr  *eth_h;
    struct ether_addr  eth_addr;

    eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
    eth_type = rte_be_to_cpu_16(eth_h->ether_type);
    l2_len = sizeof(*eth_h);
    /* frames in VPC come in with ethertype 0x8100, i.e. they are 802.1q VLAN tagged */
    if (eth_type == ETHER_TYPE_VLAN) {
        vlan_h = (struct vlan_hdr *) ((char *) eth_h + l2_len);
        eth_type = rte_be_to_cpu_16(vlan_h->eth_proto);
        l2_len += sizeof(*vlan_h);
    }
    if (eth_type != ETHER_TYPE_IPv4) {
        return 0;
    }
    ip_h = (struct ipv4_hdr *) ((char *) eth_h + l2_len);
    if (ip_h->next_proto_id != IPPROTO_UDP) {
        return 0;
    }
    udp_h = (struct udp_hdr *) ((char *) ip_h + sizeof(*ip_h));
    print_pkt(ip_h->src_addr, ip_h->dst_addr, udp_h->src_port, udp_h->dst_port, pkt->data_len);
    /* swap the source and destination addresses/ports to affect
     * the actual 'echo'ing of the packet */
    ether_addr_copy(&eth_h->s_addr, &eth_addr);
    ether_addr_copy(&eth_h->d_addr, &eth_h->s_addr);
    ether_addr_copy(&eth_addr, &eth_h->d_addr);
    ip_addr = ip_h->src_addr;
    ip_h->src_addr = ip_h->dst_addr;
    ip_h->dst_addr = ip_addr;
    udp_port = udp_h->src_port;
    udp_h->src_port = udp_h->dst_port;
    udp_h->dst_port = udp_port;
    /* set checksum parameters for HW offload */
    pkt->ol_flags |= (PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM);
    ip_h->hdr_checksum = 0;
    udp_h->dgram_cksum = ipv4_pseudo_csum(ip_h);
    return 1;
}

/*
 * Main per-lcore worker routine.
 */
static int main_loop(UNUSED void *junk)
{
    int                socket;
    uint8_t            port,
                       queue;
    uint16_t           i,
                       n_rx,
                       n_reply;
    unsigned           lcore_id;
    struct rte_mbuf   *pkt,
                      *pkts_burst[PKT_BURST];
    struct lcore_conf *conf;

    lcore_id = rte_lcore_id();
    conf = &lcore_conf[lcore_id];
    socket = socket_for_lcore(lcore_id);
    if (conf->n_rx_queue == 0) {
        RTE_LOG(INFO, USER1, "lcore %u not mapped into service\n", lcore_id);
        return 0;
    }
    RTE_LOG(INFO, USER1, "starting service on lcore %u\n", lcore_id);
    for (i = 0; i < conf->n_rx_queue; i++) {
        port = conf->rx_queues[i].port_id;
        queue = conf->rx_queues[i].queue_id;
        RTE_LOG(INFO, USER1, "-- lcore=%u port=%u rx_queue=%u\n", lcore_id, port, queue);
    }
    while (1) {
        for (i = 0; i < conf->n_rx_queue; i++) {
            port = conf->rx_queues[i].port_id;
            queue = conf->rx_queues[i].queue_id;
            n_reply = 0;
            n_rx = rte_eth_rx_burst(port, queue, pkts_burst, PKT_BURST);
            if (unlikely(n_rx == 0)) {
                continue;
            }
            for (i = 0; i < n_rx; i++) {
                pkt = pkts_burst[i];
                if (echo_single_udp_packet(pkt)) {
                    send_one(conf, pkt, port, socket);
                    n_reply++;
                } else {
                    rte_pktmbuf_free(pkt);
                }
            }
            if (n_reply > 0) {
                send_burst(conf, conf->tx_mbufs[port].len, port, socket);
                conf->tx_mbufs[port].len = 0;
            }
        }
    }
    return 0;
}

/*
 * Return how many RX queues were specified on a given port (Ethernet device).
 */
static uint8_t rx_queues_for_port(const uint8_t port)
{
    int         queue = -1;
    uint16_t    i;

    for (i = 0; i < n_lcore_params; i++) {
        if (lcore_params[i].port_id == port && lcore_params[i].queue_id > queue) {
            queue = lcore_params[i].queue_id;
        }
    }
    return (uint8_t) (++queue);
}

/*
 * Initialize a section of RAM for packet buffers per logical core.
 */
static void init_packet_buffers(unsigned num_mbuf)
{
    int      socketid;
    char     s[64];
    unsigned lcore_id;

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (!rte_lcore_is_enabled(lcore_id)) {
            continue;
        }
        socketid = socket_for_lcore(lcore_id);
        if (pktmbuf_pool[socketid] == NULL) {
            pktmbuf_pool[socketid] =
                rte_mempool_create(s,
                                   num_mbuf,
                                   MBUF_SIZE,
                                   MEMPOOL_CACHE_SIZE,
                                   sizeof(struct rte_pktmbuf_pool_private),
                                   rte_pktmbuf_pool_init, NULL,
                                   rte_pktmbuf_init, NULL,
                                   socketid, 0);
            if (!pktmbuf_pool[socketid]) {
                DIE("failed to allocate mbuf pool on socket %d\n", socketid);
            }
        }
    }
}

/*
 * Initialize a TX queue for each (lcore,port) pair.
 */
static void init_tx_queue_for_port(uint8_t port)
{
    int                rv;
    uint8_t            socketid;
    uint16_t           queue;
    unsigned           lcore_id;
    struct lcore_conf *qconf;

    queue = 0;
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (!rte_lcore_is_enabled(lcore_id)) {
            continue;
        }
        socketid = socket_for_lcore(lcore_id);
        RTE_LOG(INFO, USER1, "initializing TX queue: (lcore %u, queue %u, socket %u)\n", lcore_id, queue, socketid);
        if ((rv = rte_eth_tx_queue_setup(port, queue, nb_txd, socketid, &tx_conf))) {
            DIE("rte_eth_tx_queue_setup(%u) failed: err=%d port=%d queue=%d\n", lcore_id, rv, port, queue);
        }
        qconf = &lcore_conf[lcore_id];
        qconf->tx_queue_ids[port] = queue;
        queue++;
    }
}

/*
 * Ensure the configured (port,queue,lcore) mappings are valid.
 */
static void check_lcore_params(void)
{
    int         socketid;
    uint8_t     queue,
                lcore;
    uint16_t    i;

    for (i = 0; i < n_lcore_params; i++) {
        queue = lcore_params[i].queue_id;
        if (queue >= MAX_RX_QUEUE_PER_PORT) {
            DIE("invalid queue number: %hhu\n", queue);
        }
        lcore = lcore_params[i].lcore_id;
        if (!rte_lcore_is_enabled(lcore)) {
            DIE("lcore %hhu is not enabled in lcore mask\n", lcore);
        }
        socketid = rte_lcore_to_socket_id(lcore);
        if (socketid != 0 && !numa_on) {
            RTE_LOG(WARNING, USER1, "lcore %hhu is on socket %d with NUMA off\n", lcore, socketid);
        }
    }
}

/*
 * Initialize the mappings between Ethernet devices (ports), RX queues and
 * logical cores.
 */
static void init_lcores(void)
{
    uint8_t     lcore;
    uint16_t    i,
                n_rx_queue;

    for (i = 0; i < n_lcore_params; i++) {
        lcore = lcore_params[i].lcore_id;
        n_rx_queue = lcore_conf[lcore].n_rx_queue;
        if (n_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
            DIE("too many RX queues (%u) for lcore %u\n", (unsigned) n_rx_queue + 1, (unsigned) lcore);
        }
        lcore_conf[lcore].rx_queues[n_rx_queue].port_id = lcore_params[i].port_id;
        lcore_conf[lcore].rx_queues[n_rx_queue].queue_id = lcore_params[i].queue_id;
        lcore_conf[lcore].n_rx_queue++;
    }
}

/*
 * Configure all specified Ethernet devices, including allocating packet buffer
 * memory and TX queue rings.
 */
static void configure_ports(unsigned n_ports, uint32_t port_mask, uint32_t n_lcores)
{
    int                 rv;
    uint8_t             portid,
                        n_rx_queue;
    uint32_t            n_tx_queue;
    struct ether_addr   eth_addr;

    for (portid = 0; portid < n_ports; portid++) {
        if (!(port_mask & (1 << portid))) {
            RTE_LOG(INFO, USER1, "skipping disabled port %u\n", portid);
            continue;
        }
        n_rx_queue = rx_queues_for_port(portid);
        n_tx_queue = n_lcores;
        if (n_tx_queue > MAX_TX_QUEUE_PER_PORT) {
            n_tx_queue = MAX_TX_QUEUE_PER_PORT;
        }
        RTE_LOG(INFO, USER1, "initializing port %u: %u rx, %u tx\n", portid, (uint16_t) n_rx_queue, n_tx_queue);
        if ((rv = rte_eth_dev_configure(portid, n_rx_queue, (uint16_t) n_tx_queue, &port_conf)) < 0) {
            DIE("failed to configure Ethernet port %"PRIu8"\n", portid);
        }
        rte_eth_macaddr_get(portid, &eth_addr);
        RTE_LOG(INFO, USER1,
                "port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                portid,
                eth_addr.addr_bytes[0], eth_addr.addr_bytes[1],
                eth_addr.addr_bytes[2], eth_addr.addr_bytes[3],
                eth_addr.addr_bytes[4], eth_addr.addr_bytes[5]);
        init_packet_buffers(NUM_MBUF(n_ports, n_rx_queue, n_tx_queue, n_lcores));
        init_tx_queue_for_port(portid);
    }
}

/*
 * Initialize all RX queues rings assigned for each logical core.
 */
static void init_rx_queues(void)
{
    int                  rv;
    uint8_t              portid,
                         queueid,
                         socketid;
    uint16_t             queue;
    unsigned             lcore_id;
    struct lcore_conf   *qconf;

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (!rte_lcore_is_enabled(lcore_id)) {
            continue;
        }
        socketid = socket_for_lcore(lcore_id);
        qconf = &lcore_conf[lcore_id];
        RTE_LOG(INFO, USER1, "initializing RX queues on lcore %u\n", lcore_id);
        for (queue = 0; queue < qconf->n_rx_queue; queue++) {
            portid = qconf->rx_queues[queue].port_id;
            queueid = qconf->rx_queues[queue].queue_id;
            RTE_LOG(INFO, USER1, "-- rx_queue: port=%u queue=%u socket=%u\n", portid, queueid, socketid);
            if ((rv = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid, &rx_conf, pktmbuf_pool[socketid]))) {
                DIE("rte_eth_rx_queue_setup failed: err=%d port=%d queue=%d lcore=%d\n", rv, portid, queueid, lcore_id);
            }
        }
    }
}

/*
 * Start DPDK on all configured ports (Ethernet devices).
 */
static void start_ports(unsigned n_ports, uint32_t port_mask)
{
    int     rv;
    uint8_t portid;

    for (portid = 0; portid < n_ports; portid++) {
        if (!(port_mask & (1 << portid))) {
            continue;
        }
        rte_eth_promiscuous_enable(portid);
        if ((rv = rte_eth_dev_start(portid)) < 0) {
            DIE("rte_eth_dev_start failed: err=%d port=%d\n", rv, portid);
        }
    }
}

/*
 * Wait for all specified ports to show link UP.
 */
static void check_port_link_status(uint8_t n_ports, uint32_t port_mask)
{
    uint8_t             port,
                        count,
                        all_ports_up;
    struct rte_eth_link link;

#define CHECK_INTERVAL  100 /* milliseconds */
#define MAX_CHECK_TIME  90  /* 90 * 100ms = 9s */
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        all_ports_up = 1;
        for (port = 0; port < n_ports; port++) {
            if (!(port_mask & (1 << port))) {
                continue;
            }
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(port, &link);
            if (link.link_status == 0) {
                all_ports_up = 0;
                break;
            }
        }
        if (all_ports_up) break;
        rte_delay_ms(CHECK_INTERVAL);
    }
#undef CHECK_INTERVAL
#undef MAX_CHECK_TIME
}

/*
 * Parse enabled ports bitmask (to specify which Ethernet devices to use). On
 * failure to parse the bitmask it will return -1, which, when interpreted as
 * unsigned, will result in all bits on.
 */
static int parse_portmask(const char *arg)
{
    char            *end = NULL;
    unsigned long    mask;

    mask = strtoul(arg, &end, 16);
    if (!*arg || !end || !*end) {
        return -1;
    }
    return (!mask) ? -1 : mask;
}

/*
 * Parse given (port,queue,lcore) mapping(s). Loads the result into
 * lcore_params global if successful.
 */
static int parse_rx_config(const char *arg)
{
    enum fields {
        FLD_PORT = 0,
        FLD_QUEUE,
        FLD_LCORE,
        _NUM_FLD
    };

    int              i;
    char             s[256],
                    *end,
                    *str_fld[_NUM_FLD];
    unsigned         size;
    const char      *p,
                    *p0 = arg;
    unsigned long    int_fld[_NUM_FLD];

    n_lcore_params = 0;
    while ((p = strchr(p0, '('))) {
        ++p;
        if (!(p0 = strchr(p, ')'))) return -1;
        size = p0 - p;
        if (size >= sizeof(s)) return -1;
        snprintf(s, sizeof(s), "%.*s", size, p);
        if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD) {
            return -1;
        }
        for (i = 0; i < _NUM_FLD; i++) {
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno || end == str_fld[i] || int_fld[i] > 255) {
                return -1;
            }
        }
        if (n_lcore_params >= MAX_LCORE_PARAMS) {
            return -1;
        }
        lcore_params_array[n_lcore_params].port_id = (uint8_t) int_fld[FLD_PORT];
        lcore_params_array[n_lcore_params].queue_id = (uint8_t) int_fld[FLD_QUEUE];
        lcore_params_array[n_lcore_params].lcore_id = (uint8_t) int_fld[FLD_LCORE];
        n_lcore_params++;
    }
    lcore_params = lcore_params_array;
    return 0;
}

/*
 * Print command-line usage message.
 */
static void print_usage(const char *prgname)
{
    fprintf(stderr,
            "%s [EAL options] --"
            " [-C|--config (port,queue,lcore)[,(port,queue,lcore)...]]"
            " [-p|--portmask PORTMASK]"
            " [-N|--numa-on]"
            " [-h|--help]"
            "\n",
            prgname);
}

/*
 * Parse command-line parameters passed after the EAL parameters.
 */
static int parse_args(int argc, char **argv)
{
#define LONG_EQ(label) !strncmp(long_opts[optidx].name, (label), sizeof((label)))
    int    rv,
           opt,
           optidx;
    char  *prgname = argv[0];
    char **argvopt;

    argvopt = argv;
    while ((opt = getopt_long(argc, argvopt, "C:hNp:", long_opts, &optidx)) != EOF) {
        switch (opt) {
        case 'C':
            if (parse_rx_config(optarg)) {
                fprintf(stderr, "error: invalid RX config\n");
                print_usage(prgname);
                return -1;
            }
            break;
        case 'h':
            print_usage(prgname);
            return -1;
        case 'n':
            numa_on = true;
            break;
        case 'p':
            if (!(enabled_ports_mask = parse_portmask(optarg))) {
                fprintf(stderr, "error: invalid portmask\n");
                print_usage(prgname);
                return -1;
            }
            break;
        case 0:
            if (LONG_EQ(CMD_LINE_OPT_NUMA_ON)) {
                numa_on = true;
            }
            if (LONG_EQ(CMD_LINE_OPT_PORTMASK)) {
                if (!(enabled_ports_mask = parse_portmask(optarg))) {
                    fprintf(stderr, "error: invalid portmask\n");
                    print_usage(prgname);
                    return -1;
                }
            }
            if (LONG_EQ(CMD_LINE_OPT_RX_CONFIG)) {
                if (parse_rx_config(optarg)) {
                    fprintf(stderr, "error: invalid RX config\n");
                    print_usage(prgname);
                    return -1;
                }
            }
            if (LONG_EQ(CMD_LINE_OPT_HELP)) {
                print_usage(prgname);
                return -1;
            }
            break;
        }
    }
    if (optind >= 0) {
        argv[optind - 1] = prgname;
    }
    rv = optind - 1;
    optind = 0;
    return rv;
#undef LONG_EQ
}

static void init_nics(void)
{
    unsigned n_ports;

    check_lcore_params();
    init_lcores();
    if ((n_ports = rte_eth_dev_count()) == 0) {
        DIE("no Ethernet ports detected\n");
    }
    RTE_LOG(INFO, USER1, "%u Ethernet port(s) detected\n", n_ports);
    configure_ports(n_ports, enabled_ports_mask, rte_lcore_count());
    init_rx_queues();
    start_ports(n_ports, enabled_ports_mask);
    check_port_link_status(n_ports, enabled_ports_mask);
}

int main(int argc, char **argv)
{
    int rv;

    if (getenv("LOG_VERBOSE")) {
        rte_set_log_level(RTE_LOG_DEBUG);
    } else {
        rte_set_log_level(RTE_LOG_INFO);
    }
    if ((rv = rte_eal_init(argc, argv)) < 0) {
        DIE("invalid EAL parameters\n");
    }
    argc -= rv;
    argv += rv;
    if ((rv = parse_args(argc, argv)) < 0) {
        DIE("invalid server parameters\n");
    }
    init_nics();
    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
    rte_eal_mp_wait_lcore();
    return 0;
}
