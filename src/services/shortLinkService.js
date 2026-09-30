import { generateWebPath } from '../utils.js';
import { MissingDependencyError, InvalidPayloadError } from './errors.js';

const SHORT_CODE_REGEX = /^[a-zA-Z0-9_-]{4,64}$/;
const RESERVED_PREFIX_REGEX = /^(clash|singbox|surge|xray)_/i;

export class ShortLinkService {
    constructor(kv, options = {}) {
        this.kv = kv;
        this.options = options;
    }

    ensureKv() {
        if (!this.kv) {
            throw new MissingDependencyError('Short link service requires a KV store');
        }
        return this.kv;
    }

    async createShortLink(queryString, providedCode) {
        const kv = this.ensureKv();
        let shortCode = providedCode;

        if (shortCode) {
            if (!SHORT_CODE_REGEX.test(shortCode)) {
                throw new InvalidPayloadError('Invalid custom short code format');
            }
            if (RESERVED_PREFIX_REGEX.test(shortCode)) {
                throw new InvalidPayloadError('Short code uses a reserved prefix');
            }
            const existing = await kv.get(shortCode);
            if (existing && existing !== queryString) {
                throw new InvalidPayloadError('Short code already in use');
            }
        } else {
            shortCode = generateWebPath();
        }

        const ttl = this.options.shortLinkTtlSeconds;
        const putOptions = ttl ? { expirationTtl: ttl } : undefined;
        await kv.put(shortCode, queryString, putOptions);
        return shortCode;
    }

    async resolveShortCode(code) {
        const kv = this.ensureKv();
        return kv.get(code);
    }
}
