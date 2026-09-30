import { parseServerInfo, parseUrlParams, createTlsConfig, createTransportConfig, safeDecodeURIComponent } from '../../utils.js';

export function parseTrojan(url) {
    if (!url || typeof url !== 'string') return null;

    try {
        const { addressPart, params, name } = parseUrlParams(url);
        const [password, serverInfo] = addressPart.split('@');
        if (!serverInfo) return null;
        const { host, port } = parseServerInfo(serverInfo);

        const parsedURL = parseServerInfo(addressPart);
        const tls = createTlsConfig(params);
        const transport = params.type !== 'tcp' ? createTransportConfig(params) : undefined;
        return {
            type: 'trojan',
            tag: name,
            server: host,
            server_port: port,
            password: safeDecodeURIComponent(password) || parsedURL.username,
            network: 'tcp',
            tcp_fast_open: false,
            tls,
            transport,
            flow: params.flow ?? undefined
        };
    } catch (e) {
        console.error('Failed to parse trojan URL:', e);
        return null;
    }
}
