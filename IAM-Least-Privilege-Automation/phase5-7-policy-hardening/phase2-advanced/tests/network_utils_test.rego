package aegis.network

test_private_10_not_public {
    not is_public_cidr("10.50.1.0/24")
}

test_private_172_not_public {
    not is_public_cidr("172.20.5.0/24")
}

test_private_192_not_public {
    not is_public_cidr("192.168.20.0/24")
}

test_public_ipv4_google {
    is_public_cidr("8.8.8.0/24")
}

test_public_ipv4_cloudflare {
    is_public_cidr("1.1.1.0/24")
}

test_loopback_ipv4_not_public {
    not is_public_cidr("127.0.0.0/8")
}

test_link_local_ipv4_not_public {
    not is_public_cidr("169.254.0.0/16")
}

test_documentation_ipv4_not_public {
    not is_public_cidr("192.0.2.0/24")
}

test_ipv6_ula_not_public {
    not is_public_cidr("fc00::/7")
}

test_ipv6_link_local_not_public {
    not is_public_cidr("fe80::/10")
}

test_ipv6_loopback_not_public {
    not is_public_cidr("::1/128")
}

test_ipv6_documentation_not_public {
    not is_public_cidr("2001:db8::/32")
}

test_ipv4_anywhere_is_public_exposure {
    is_public_cidr("0.0.0.0/0")
}

test_ipv6_anywhere_is_public_exposure {
    is_public_cidr("::/0")
}

test_public_ipv4_boundary_lower_half {
    is_public_cidr("0.0.0.0/1")
}

test_public_ipv4_boundary_upper_half {
    is_public_cidr("128.0.0.0/1")
}
test_public_ipv6 {
    is_public_cidr("2001:4860::/32")
}

