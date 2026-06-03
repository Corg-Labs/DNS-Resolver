# DNS-Resolver in C

A **real DNS resolver** that speaks the DNS wire protocol over **UDP**. It hand-builds query packets, sends them to Google's `8.8.8.8` nameserver on port 53, and parses the binary response — decoding **A**, **AAAA**, **MX**, **TXT**, **NS**, and **CNAME** resource records. No system resolver libraries are used; every byte is constructed manually.

Part of the [Corg-Labs](https://github.com/Corg-Labs) collection of single-file C programs.

---

# Features
- Wire-format query construction using `#pragma pack(1)` structs
- Handles DNS name compression pointers in responses
- Decodes A (IPv4), AAAA (IPv6), MX, TXT, CNAME, and NS record types
- 5-second receive timeout via `SO_RCVTIMEO`
- Displays query type, answer count, TTL, and resolved value for each RR

---

# Tutorial

## 1. DNS Wire Format: The Header

Every DNS message begins with a fixed 12-byte header packed to match the wire layout exactly:

```c
#pragma pack(push, 1)
typedef struct {
    uint16_t id;       /* random transaction ID         */
    uint16_t flags;    /* QR, opcode, AA, TC, RD, RA…  */
    uint16_t qdcount;  /* number of questions           */
    uint16_t ancount;  /* number of answers             */
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;
#pragma pack(pop)
```

The query sets `flags = 0x0100` (RD=1, recursion desired). All multi-byte fields use `htons()` for big-endian network byte order.

## 2. Encoding a Domain Name

DNS names are length-prefixed labels, not plain strings:

```
"www.google.com"  →  \x03 w w w \x06 g o o g l e \x03 c o m \x00
```

`encode_name()` scans for `.` delimiters, writes each label length followed by the label bytes, and appends a zero terminator.

## 3. UDP Socket Setup

```c
int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

struct timeval tv = { .tv_sec = 5 };
setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

struct sockaddr_in srv = {
    .sin_family = AF_INET,
    .sin_port   = htons(53),
};
inet_pton(AF_INET, "8.8.8.8", &srv.sin_addr);

sendto(sock, query, qlen, 0, (struct sockaddr *)&srv, sizeof(srv));
ssize_t rlen = recvfrom(sock, response, sizeof(response), 0, NULL, NULL);
```

## 4. DNS Name Compression Pointers

A pointer is identified by the top two bits being set (`0xC0`):

```c
if ((len & 0xC0) == 0xC0) {
    int target = ((len & 0x3F) << 8) | msg[pos + 1];
    pos = target;   /* jump to referenced offset */
    continue;
}
```

`decode_name()` follows pointer chains transparently until it reaches a zero-length label.

## 5. Decoding Record Types

```c
if (type == QTYPE_A && rdlen == 4) {
    inet_ntop(AF_INET, msg + pos, ip, sizeof(ip));
} else if (type == QTYPE_AAAA && rdlen == 16) {
    inet_ntop(AF_INET6, msg + pos, ip, sizeof(ip));
} else if (type == QTYPE_MX) {
    uint16_t pref = ntohs(*(uint16_t *)(msg + pos));
    decode_name(msg, msglen, pos + 2, mx, sizeof(mx));
} else if (type == QTYPE_TXT) {
    uint8_t tlen = msg[tpos++];
    fwrite(msg + tpos, 1, tlen, stdout);
}
```

---

# Build

```
gcc dns.c -o dns
```

# Run

```
./dns google.com
./dns -AAAA ipv6.google.com
./dns -MX gmail.com
./dns -TXT google.com
```

---

# Concepts Practiced
- DNS wire protocol (RFC 1035)
- UDP socket programming (`SOCK_DGRAM`)
- Network byte order (`htons`/`ntohs`/`ntohl`)
- Binary packet construction and parsing
- DNS name compression pointer resolution

# Dependencies
Standard C library + POSIX sockets (`arpa/inet.h`, `netinet/in.h`, `sys/socket.h`). No external libraries.
