import { parseServerInfo, parseUrlParams, parseArray, parseBool, safeDecodeURIComponent } from '../../utils.js';

export function parseTuic(url) {
    if (!url || typeof url !== 'string') return null;

    try {
        const { addressPart, params, name } = parseUrlParams(url);
        const [userinfo, serverInfo] = addressPart.split('@');
        if (!serverInfo || !userinfo) return null;
        const { host, port } = parseServerInfo(serverInfo);
        const tls = {
            enabled: true,
            server_name: params.sni,
            alpn: parseArray(params.alpn),
            insecure: parseBool(params['skip-cert-verify'] ?? params.insecure ?? params.allowInsecure, true)
        };

        const decodedUserInfo = safeDecodeURIComponent(userinfo);
        const colonIndex = decodedUserInfo.indexOf(':');
        const uuid = colonIndex !== -1 ? decodedUserInfo.slice(0, colonIndex) : decodedUserInfo;
        const password = colonIndex !== -1 ? decodedUserInfo.slice(colonIndex + 1) : '';

        return {
            tag: name,
            type: 'tuic',
            server: host,
            server_port: port,
            uuid,
            password,
            congestion_control: params.congestion_control,
            tls,
            flow: params.flow ?? undefined,
            udp_relay_mode: params['udp-relay-mode'] || params.udp_relay_mode,
            zero_rtt: parseBool(params['zero-rtt'], undefined),
            reduce_rtt: parseBool(params['reduce-rtt'], undefined),
            fast_open: parseBool(params['fast-open'], undefined),
            disable_sni: parseBool(params['disable-sni'], undefined)
        };
    } catch (e) {
        console.error('Failed to parse tuic URL:', e);
        return null;
    }
}
