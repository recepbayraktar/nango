import crypto from 'node:crypto';

const DEFAULT_TOLERANCE_SECONDS = 5 * 60;

/**
 * Constant-time comparison that tolerates mismatched lengths.
 * timingSafeEqual throws when the two buffers differ in length, which turns a
 * malformed signature into a 500 instead of a 401.
 */
export function safeCompare(expected: string, received: string, encoding: BufferEncoding = 'utf8'): boolean {
    try {
        const expectedBuffer = Buffer.from(expected, encoding);
        const receivedBuffer = Buffer.from(received, encoding);

        return expectedBuffer.length > 0 && expectedBuffer.length === receivedBuffer.length && crypto.timingSafeEqual(expectedBuffer, receivedBuffer);
    } catch {
        return false;
    }
}

export interface HmacOptions {
    secret: string | Buffer;
    rawBody: string;
    signature: string;
    algorithm?: 'sha1' | 'sha256';
    /** Encoding of the digest, and of the signature we compare it against. */
    digest?: 'hex' | 'base64';
    /** Prefix the provider puts in front of the digest, e.g. `sha256=`. Stripped from the received signature when present. */
    prefix?: string;
}

/**
 * HMAC over the raw body, compared in constant time. Covers the scheme used by
 * most providers, differing only in algorithm, digest encoding and prefix.
 */
export function validateHmacSignature({ secret, rawBody, signature, algorithm = 'sha256', digest = 'hex', prefix }: HmacOptions): boolean {
    if (!secret || (typeof secret === 'string' && secret.length === 0) || !signature) {
        return false;
    }

    const expected = crypto.createHmac(algorithm, secret).update(rawBody, 'utf8').digest(digest);
    const received = prefix && signature.startsWith(prefix) ? signature.slice(prefix.length) : signature;

    return safeCompare(expected, received, digest === 'hex' ? 'hex' : 'base64');
}

export interface SvixOptions {
    secret: string;
    headers: Record<string, any>;
    rawBody: string;
    toleranceSeconds?: number;
}

export type SvixResult = 'valid' | 'invalid' | 'missing_headers' | 'stale_timestamp';

/**
 * Verify a signature following the standard-webhooks (Svix) scheme, used as-is by
 * GitLab, Fathom and Folk.
 *
 * Signed content is `{webhook-id}.{webhook-timestamp}.{rawBody}`, the secret is a
 * base64 key optionally prefixed with `whsec_`, and `webhook-signature` carries one
 * or more space separated `v1,<base64>` signatures.
 *
 * https://www.standardwebhooks.com/
 */
export function validateSvixSignature({ secret, headers, rawBody, toleranceSeconds = DEFAULT_TOLERANCE_SECONDS }: SvixOptions): SvixResult {
    const msgId = headers['webhook-id'] || headers['svix-id'];
    const msgTimestamp = headers['webhook-timestamp'] || headers['svix-timestamp'];
    const msgSignature = headers['webhook-signature'] || headers['svix-signature'];

    if (!msgId || !msgTimestamp || !msgSignature || !secret) {
        return 'missing_headers';
    }

    const timestamp = Number(msgTimestamp);
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(timestamp) || Math.abs(now - timestamp) > toleranceSeconds) {
        return 'stale_timestamp';
    }

    const key = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');
    if (key.length === 0) {
        return 'invalid';
    }

    const expected = crypto.createHmac('sha256', key).update(`${msgId}.${timestamp}.${rawBody}`).digest('base64');

    const matched = String(msgSignature)
        .split(' ')
        .map((sig) => sig.replace(/^v1,/, ''))
        .some((sig) => safeCompare(expected, sig, 'base64'));

    return matched ? 'valid' : 'invalid';
}
