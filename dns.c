/*
 * dns.c — DNS resolver over UDP
 * Corg-Labs educational networking demo
 *
 * Build:  gcc dns.c -o dns
 * Usage:  ./dns google.com
 *         ./dns -MX gmail.com
 *         ./dns -AAAA ipv6.google.com
 *         ./dns -TXT google.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

/* ── constants ────────────────────────────────────────────────── */
#define DNS_SERVER      "8.8.8.8"
#define DNS_PORT        53
#define BUF_SIZE        512
#define MAX_LABEL       63
#define MAX_NAME        255

/* Query types */
#define QTYPE_A         1
#define QTYPE_NS        2
#define QTYPE_CNAME     5
#define QTYPE_MX        15
#define QTYPE_TXT       16
#define QTYPE_AAAA      28

/* ── wire-format structs (packed, big-endian) ─────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} dns_question_tail_t;

typedef struct {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
} dns_rr_tail_t;
#pragma pack(pop)

/* ── helpers ──────────────────────────────────────────────────── */

/* Encode "www.google.com" → \x03www\x06google\x03com\x00 */
static int encode_name(const char *name, uint8_t *out, int outlen) {
    int pos = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int lablen = dot ? (int)(dot - p) : (int)strlen(p);
        if (lablen > MAX_LABEL || pos + lablen + 1 >= outlen) return -1;
        out[pos++] = (uint8_t)lablen;
        memcpy(out + pos, p, lablen);
        pos += lablen;
        p += lablen;
        if (*p == '.') p++;
    }
    out[pos++] = 0;
    return pos;
}

/* Follow compression pointers and labels; return bytes consumed (not counting jumps). */
static int decode_name(const uint8_t *msg, int msglen, int offset, char *out, int outlen) {
    int pos = offset, written = 0, jumped = 0, ret = -1;
    out[0] = '\0';
    while (pos < msglen) {
        uint8_t len = msg[pos];
        if ((len & 0xC0) == 0xC0) {
            /* compression pointer */
            if (pos + 1 >= msglen) return -1;
            if (!jumped) ret = pos + 2;
            jumped = 1;
            pos = ((len & 0x3F) << 8) | msg[pos + 1];
            continue;
        }
        if (len == 0) {
            if (!jumped) ret = pos + 1;
            break;
        }
        pos++;
        if (written > 0) {
            if (written >= outlen - 1) return -1;
            out[written++] = '.';
        }
        if (written + len >= outlen) return -1;
        memcpy(out + written, msg + pos, len);
        written += len;
        out[written] = '\0';
        pos += len;
    }
    return ret;
}

static const char *qtype_name(uint16_t t) {
    switch (t) {
        case QTYPE_A:     return "A";
        case QTYPE_NS:    return "NS";
        case QTYPE_CNAME: return "CNAME";
        case QTYPE_MX:    return "MX";
        case QTYPE_TXT:   return "TXT";
        case QTYPE_AAAA:  return "AAAA";
        default:          return "???";
    }
}

/* ── build query packet ───────────────────────────────────────── */
static int build_query(const char *name, uint16_t qtype, uint8_t *buf, int buflen) {
    memset(buf, 0, buflen);
    dns_header_t *h = (dns_header_t *)buf;
    h->id      = htons((uint16_t)(getpid() & 0xFFFF));
    h->flags   = htons(0x0100);   /* RD = 1 (recursion desired) */
    h->qdcount = htons(1);

    int pos = sizeof(dns_header_t);
    int nlen = encode_name(name, buf + pos, buflen - pos);
    if (nlen < 0) { fprintf(stderr, "Name encoding failed\n"); return -1; }
    pos += nlen;

    dns_question_tail_t *qt = (dns_question_tail_t *)(buf + pos);
    qt->qtype  = htons(qtype);
    qt->qclass = htons(1); /* IN */
    pos += sizeof(dns_question_tail_t);
    return pos;
}

/* ── parse and print answer section ──────────────────────────── */
static void parse_response(const uint8_t *msg, int msglen, uint16_t qtype) {
    if (msglen < (int)sizeof(dns_header_t)) { fprintf(stderr, "Response too short\n"); return; }
    const dns_header_t *h = (const dns_header_t *)msg;

    uint16_t flags   = ntohs(h->flags);
    uint16_t rcode   = flags & 0x0F;
    uint16_t ancount = ntohs(h->ancount);
    uint16_t qdcount = ntohs(h->qdcount);

    if (rcode != 0) {
        const char *rcodes[] = {"NOERROR","FORMERR","SERVFAIL","NXDOMAIN","NOTIMP","REFUSED"};
        fprintf(stderr, "DNS error: %s\n", rcode < 6 ? rcodes[rcode] : "UNKNOWN");
        return;
    }
    printf("Query type : %s\n", qtype_name(qtype));
    printf("Answers    : %u\n\n", ancount);

    /* Skip question section */
    int pos = sizeof(dns_header_t);
    char name[MAX_NAME + 1];
    for (int i = 0; i < qdcount; i++) {
        pos = decode_name(msg, msglen, pos, name, sizeof(name));
        if (pos < 0) return;
        pos += sizeof(dns_question_tail_t);
    }

    /* Parse answer RRs */
    for (int i = 0; i < ancount && pos < msglen; i++) {
        pos = decode_name(msg, msglen, pos, name, sizeof(name));
        if (pos < 0) return;
        if (pos + (int)sizeof(dns_rr_tail_t) > msglen) return;

        dns_rr_tail_t rr;
        memcpy(&rr, msg + pos, sizeof(rr));
        pos += sizeof(dns_rr_tail_t);
        uint16_t type   = ntohs(rr.type);
        uint32_t ttl    = ntohl(rr.ttl);
        uint16_t rdlen  = ntohs(rr.rdlength);

        printf("  [%s] TTL=%u  ", qtype_name(type), ttl);

        if (type == QTYPE_A && rdlen == 4) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, msg + pos, ip, sizeof(ip));
            printf("%s", ip);
        } else if (type == QTYPE_AAAA && rdlen == 16) {
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, msg + pos, ip, sizeof(ip));
            printf("%s", ip);
        } else if (type == QTYPE_CNAME || type == QTYPE_NS) {
            char cname[MAX_NAME + 1];
            decode_name(msg, msglen, pos, cname, sizeof(cname));
            printf("%s", cname);
        } else if (type == QTYPE_MX) {
            uint16_t pref = ntohs(*(uint16_t *)(msg + pos));
            char mx[MAX_NAME + 1];
            decode_name(msg, msglen, pos + 2, mx, sizeof(mx));
            printf("pref=%u  %s", pref, mx);
        } else if (type == QTYPE_TXT) {
            int tpos = pos, end = pos + rdlen;
            printf("\"");
            while (tpos < end) {
                uint8_t tlen = msg[tpos++];
                for (int j = 0; j < tlen && tpos < end; j++, tpos++)
                    putchar(msg[tpos] >= 32 ? msg[tpos] : '.');
            }
            printf("\"");
        } else {
            printf("<rdlen=%u>", rdlen);
        }
        printf("\n");
        pos += rdlen;
    }
}

/* ── main ─────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-A|-AAAA|-MX|-TXT] <hostname>\n", argv[0]);
        return 1;
    }

    uint16_t qtype = QTYPE_A;
    const char *hostname = NULL;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "-A")    == 0) qtype = QTYPE_A;
        else if (strcmp(argv[i], "-AAAA") == 0) qtype = QTYPE_AAAA;
        else if (strcmp(argv[i], "-MX")   == 0) qtype = QTYPE_MX;
        else if (strcmp(argv[i], "-TXT")  == 0) qtype = QTYPE_TXT;
        else if (strcmp(argv[i], "-NS")   == 0) qtype = QTYPE_NS;
        else hostname = argv[i];
    }
    if (!hostname) { fprintf(stderr, "No hostname specified.\n"); return 1; }

    /* Build packet */
    uint8_t query[BUF_SIZE], response[BUF_SIZE * 8];
    int qlen = build_query(hostname, qtype, query, sizeof(query));
    if (qlen < 0) return 1;

    /* UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) { perror("socket"); return 1; }

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in srv = {
        .sin_family = AF_INET,
        .sin_port   = htons(DNS_PORT),
    };
    inet_pton(AF_INET, DNS_SERVER, &srv.sin_addr);

    printf("Querying %s for %s (%s)...\n\n", DNS_SERVER, hostname, qtype_name(qtype));

    if (sendto(sock, query, qlen, 0, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("sendto"); close(sock); return 1;
    }

    socklen_t srvlen = sizeof(srv);
    ssize_t rlen = recvfrom(sock, response, sizeof(response), 0,
                            (struct sockaddr *)&srv, &srvlen);
    close(sock);
    if (rlen < 0) { perror("recvfrom (timeout?)"); return 1; }

    parse_response(response, (int)rlen, qtype);
    return 0;
}
