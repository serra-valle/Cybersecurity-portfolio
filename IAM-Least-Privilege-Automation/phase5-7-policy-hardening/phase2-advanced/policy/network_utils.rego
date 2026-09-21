package aegis.network

# RFC1918 private IPv4 ranges.
private_ipv4_ranges := {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
}

# Selected special-purpose IPv4 ranges that should not be
# classified as ordinary publicly routable address space.
special_ipv4_ranges := {
    "0.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "192.0.2.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
}

# Selected non-public IPv6 ranges.
non_public_ipv6_ranges := {
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "2001:db8::/32",
    "ff00::/8",
}

is_ipv4(cidr) {
    contains(cidr, ".")
}

is_ipv6(cidr) {
    contains(cidr, ":")
}

is_private_ipv4(cidr) {
    network := private_ipv4_ranges[_]
    net.cidr_contains(network, cidr)
}

is_special_ipv4(cidr) {
    network := special_ipv4_ranges[_]
    net.cidr_contains(network, cidr)
}

is_non_public_ipv6(cidr) {
    network := non_public_ipv6_ranges[_]
    net.cidr_contains(network, cidr)
}

is_public_cidr(cidr) {
    is_ipv4(cidr)
    net.cidr_contains("0.0.0.0/0", cidr)
    not is_private_ipv4(cidr)
    not is_special_ipv4(cidr)
}

is_public_cidr(cidr) {
    is_ipv6(cidr)
    net.cidr_contains("::/0", cidr)
    not is_non_public_ipv6(cidr)
}
