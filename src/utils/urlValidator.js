/**
 * URL validation utilities to mitigate SSRF and unwanted network access
 */

function isPrivateOrLocalIp(host) {
    // Standard IPv4 dotted-decimal
    const ipv4Match = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (ipv4Match) {
        const [o1, o2, o3, o4] = [
            Number(ipv4Match[1]),
            Number(ipv4Match[2]),
            Number(ipv4Match[3]),
            Number(ipv4Match[4])
        ];
        if (o1 === 0) return true; // 0.0.0.0/8 current network
        if (o1 === 127) return true; // 127.0.0.0/8 loopback
        if (o1 === 10) return true; // 10.0.0.0/8 private network
        if (o1 === 172 && o2 >= 16 && o2 <= 31) return true; // 172.16.0.0/12 private network
        if (o1 === 192 && o2 === 168) return true; // 192.168.0.0/16 private network
        if (o1 === 169 && o2 === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
        if (o1 === 100 && o2 >= 64 && o2 <= 127) return true; // 100.64.0.0/10 carrier-grade NAT
        if (o1 >= 224) return true; // Multicast / reserved
        return false;
    }

    // IPv6 checks
    if (host.includes(':')) {
        const cleanHost = host.toLowerCase();
        if (cleanHost === '::1' || cleanHost === '::') return true;
        if (cleanHost.startsWith('::ffff:')) {
            const mapped = cleanHost.slice(7);
            if (mapped.includes('.')) {
                return isPrivateOrLocalIp(mapped);
            }
            const parts = mapped.split(':');
            if (parts.length === 2) {
                const high = parseInt(parts[0], 16);
                const low = parseInt(parts[1], 16);
                const o1 = (high >> 8) & 0xff;
                const o2 = high & 0xff;
                const o3 = (low >> 8) & 0xff;
                const o4 = low & 0xff;
                return isPrivateOrLocalIp(`${o1}.${o2}.${o3}.${o4}`);
            }
            return true;
        }
        if (cleanHost.startsWith('fc') || cleanHost.startsWith('fd')) return true; // ULA fc00::/7
        if (/^fe[89ab]/i.test(cleanHost)) return true; // link-local fe80::/10
        return false;
    }

    return false;
}

export function isSafeFetchUrl(urlString) {
    if (typeof urlString !== 'string' || !urlString.trim()) {
        return false;
    }

    let parsed;
    try {
        parsed = new URL(urlString.trim());
    } catch {
        return false;
    }

    // Only allow HTTP and HTTPS protocols
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return false;
    }

    let hostname = parsed.hostname.toLowerCase();
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
        hostname = hostname.slice(1, -1);
    }

    // Reject localhost, local domains, and internal hostnames
    if (
        hostname === 'localhost' ||
        hostname.endsWith('.localhost') ||
        hostname.endsWith('.local') ||
        hostname.endsWith('.internal') ||
        hostname.endsWith('.lan')
    ) {
        return false;
    }

    // Reject private/loopback/metadata IP addresses
    if (isPrivateOrLocalIp(hostname)) {
        return false;
    }

    return true;
}
