import { describe, it, expect, vi } from 'vitest';
import { parseUrlParams, parseServerInfo, safeDecodeURIComponent } from '../src/utils.js';
import { parseVmess } from '../src/parsers/protocols/vmessParser.js';
import { parseShadowsocks } from '../src/parsers/protocols/shadowsocksParser.js';
import { parseVless } from '../src/parsers/protocols/vlessParser.js';
import { parseTrojan } from '../src/parsers/protocols/trojanParser.js';
import { parseTuic } from '../src/parsers/protocols/tuicParser.js';
import { isSafeFetchUrl } from '../src/utils/urlValidator.js';
import { ShortLinkService } from '../src/services/shortLinkService.js';
import { InvalidPayloadError } from '../src/services/errors.js';
import { generateRules } from '../src/config/ruleGenerators.js';

describe('Security & Bug Fixes', () => {
    describe('parseUrlParams & parseServerInfo', () => {
        it('should correctly parse tag and server info when no query parameters are present', () => {
            const url = 'trojan://password123@1.2.3.4:443#HongKong-Node';
            const { addressPart, params, name } = parseUrlParams(url);
            expect(name).toBe('HongKong-Node');
            expect(addressPart).toBe('password123@1.2.3.4:443');
            expect(params).toEqual({});

            const trojanConfig = parseTrojan(url);
            expect(trojanConfig).toBeTruthy();
            expect(trojanConfig.tag).toBe('HongKong-Node');
            expect(trojanConfig.server).toBe('1.2.3.4');
            expect(trojanConfig.server_port).toBe(443);
            expect(trojanConfig.password).toBe('password123');
        });

        it('should handle domain without port without truncating domain name', () => {
            const info = parseServerInfo('proxy.example.com');
            expect(info.host).toBe('proxy.example.com');
            expect(info.port).toBeNull();
        });

        it('should handle IPv6 server info with port', () => {
            const info = parseServerInfo('[2001:db8::1]:8443');
            expect(info.host).toBe('2001:db8::1');
            expect(info.port).toBe(8443);
        });
    });

    describe('Protocol parsers resiliency against malformed input', () => {
        it('parseVmess returns null on invalid JSON without throwing', () => {
            expect(parseVmess('vmess://not-valid-base64-json')).toBeNull();
            expect(parseVmess('vmess://bm90IGpzb24=')).toBeNull(); // base64 of "not json"
        });

        it('parseVmess handles malformed URI in tag override without throwing', () => {
            const validVmessJson = Buffer.from(JSON.stringify({
                v: '2',
                ps: 'test',
                add: '1.2.3.4',
                port: 443,
                id: '00000000-0000-0000-0000-000000000000',
                net: 'tcp'
            })).toString('base64');
            const res = parseVmess(`vmess://${validVmessJson}#%80bad-uri`);
            expect(res).toBeTruthy();
            expect(res.tag).toBe('%80bad-uri');
        });

        it('parseShadowsocks handles malformed percent encoding without throwing', () => {
            const res = parseShadowsocks('ss://YWVzLTEyOC1nY206cGFzc3dvcmRAMS4yLjMuNDo4NDQz#%80malformed');
            expect(res).toBeTruthy();
            expect(res.tag).toBe('%80malformed');
        });

        it('parseVless returns null on invalid format without throwing', () => {
            expect(parseVless('vless://invalid-without-at')).toBeNull();
        });

        it('parseTuic returns null on missing userinfo or server without throwing', () => {
            expect(parseTuic('tuic://missing-at-server')).toBeNull();
        });
    });

    describe('SSRF Protection (isSafeFetchUrl)', () => {
        it('blocks loopback, private IPs, and cloud metadata addresses', () => {
            expect(isSafeFetchUrl('http://127.0.0.1/admin')).toBe(false);
            expect(isSafeFetchUrl('http://localhost:8080')).toBe(false);
            expect(isSafeFetchUrl('http://sub.localhost/test')).toBe(false);
            expect(isSafeFetchUrl('http://server.local/api')).toBe(false);
            expect(isSafeFetchUrl('http://169.254.169.254/latest/meta-data/')).toBe(false);
            expect(isSafeFetchUrl('http://10.0.0.1:6379/')).toBe(false);
            expect(isSafeFetchUrl('http://172.16.0.5:8080/')).toBe(false);
            expect(isSafeFetchUrl('http://192.168.1.100/')).toBe(false);
            expect(isSafeFetchUrl('http://[::1]/')).toBe(false);
            expect(isSafeFetchUrl('http://[::ffff:127.0.0.1]/')).toBe(false);
            expect(isSafeFetchUrl('http://[fe80::1]/')).toBe(false);
            expect(isSafeFetchUrl('file:///etc/passwd')).toBe(false);
            expect(isSafeFetchUrl('ftp://example.com/')).toBe(false);
        });

        it('allows valid public HTTP and HTTPS URLs', () => {
            expect(isSafeFetchUrl('https://example.com/subscription')).toBe(true);
            expect(isSafeFetchUrl('http://8.8.8.8/sub')).toBe(true);
            expect(isSafeFetchUrl('https://raw.githubusercontent.com/user/repo/main/sub.txt')).toBe(true);
        });
    });

    describe('ShortLinkService Custom Code Validation & Overwrite Protection', () => {
        it('rejects shortCode with invalid characters', async () => {
            const kvMock = { put: vi.fn(), get: vi.fn().mockResolvedValue(null) };
            const service = new ShortLinkService(kvMock);

            await expect(service.createShortLink('?config=foo', 'bad/code')).rejects.toThrow(InvalidPayloadError);
            await expect(service.createShortLink('?config=foo', 'a b c')).rejects.toThrow(InvalidPayloadError);
            await expect(service.createShortLink('?config=foo', 'ab')).rejects.toThrow(InvalidPayloadError); // too short
        });

        it('rejects shortCode using reserved config prefixes', async () => {
            const kvMock = { put: vi.fn(), get: vi.fn().mockResolvedValue(null) };
            const service = new ShortLinkService(kvMock);

            await expect(service.createShortLink('?config=foo', 'clash_override')).rejects.toThrow(InvalidPayloadError);
            await expect(service.createShortLink('?config=foo', 'singbox_12345678')).rejects.toThrow(InvalidPayloadError);
        });

        it('rejects overwriting an existing short code with different query', async () => {
            const kvMock = {
                put: vi.fn(),
                get: vi.fn().mockImplementation(async (key) => key === 'existing-code' ? '?config=original' : null)
            };
            const service = new ShortLinkService(kvMock);

            await expect(service.createShortLink('?config=different', 'existing-code')).rejects.toThrow('Short code already in use');
        });
    });

    describe('generateRules in-place mutation', () => {
        it('does not mutate the caller customRules array', () => {
            const originalCustomRules = [
                { name: 'Rule1', site: ['google'] },
                { name: 'Rule2', site: ['twitter'] }
            ];
            const rulesCopy = [...originalCustomRules];

            generateRules(['Direct'], originalCustomRules);

            expect(originalCustomRules[0].name).toBe(rulesCopy[0].name);
            expect(originalCustomRules[1].name).toBe(rulesCopy[1].name);
        });
    });
});
