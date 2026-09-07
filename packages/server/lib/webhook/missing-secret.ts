import { OtlpSpan } from '@nangohq/logs';
import { getLogger, metrics } from '@nangohq/utils';

import type { InternalNango } from './internal-nango.js';

const logger = getLogger('Webhook.MissingSecret');

/**
 * One warning per key per window. Incoming webhook volume is high enough that a log
 * operation per request would flood the customer's logs and our storage, and the warning
 * says the same thing every time.
 */
const WARN_INTERVAL_MS = 60 * 60 * 1000;
const MAX_TRACKED_KEYS = 10_000;
const lastWarnedAt = new Map<string, number>();

function shouldWarn(key: string): boolean {
    const now = Date.now();
    const previous = lastWarnedAt.get(key);

    if (previous && now - previous < WARN_INTERVAL_MS) {
        return false;
    }

    // Providers with a per-connection secret warn per connection, so the map is unbounded
    // without this. Dropping the oldest entry only costs a duplicate warning.
    if (lastWarnedAt.size >= MAX_TRACKED_KEYS && !previous) {
        const oldest = lastWarnedAt.keys().next();
        if (!oldest.done) {
            lastWarnedAt.delete(oldest.value);
        }
    }

    lastWarnedAt.set(key, now);
    return true;
}

/** Completes "<remediation> to enable verification." */
const DEFAULT_REMEDIATION = 'Set the webhook secret on the integration';

/**
 * Surface a skipped signature check in the customer's own logs.
 *
 * Our posture when a provider supports signature verification but no webhook secret is
 * configured is to let the webhook through, so the only signal the customer gets that
 * their traffic is unverified is this warning.
 *
 * `remediation` says where to set the secret, because that differs per provider. Pass a
 * phrase that completes "<remediation> to enable verification".
 *
 * `connection` scopes both the warning and its throttle for providers whose secret lives
 * on the connection, so one unconfigured connection neither mislabels the others nor
 * mutes them.
 */
export function warnMissingWebhookSecret(
    nango: InternalNango,
    {
        reason,
        remediation = DEFAULT_REMEDIATION,
        connection
    }: { reason: string; remediation?: string | undefined; connection?: { id: number; name: string } | undefined }
): void {
    const integrationId = nango.integration.id;

    metrics.increment(metrics.Types.WEBHOOK_INCOMING_UNVERIFIED, 1, {
        provider: nango.integration.provider,
        reason
    });

    if (!integrationId || !shouldWarn(`${integrationId}:${reason}:${connection?.id ?? ''}`)) {
        return;
    }

    const scope = connection ? 'this connection' : 'this integration';

    void (async () => {
        try {
            const logCtx = await nango.logContextGetter.create(
                { operation: { type: 'webhook', action: 'incoming' }, expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString() },
                {
                    account: nango.team,
                    environment: nango.environment,
                    integration: { id: integrationId, name: nango.integration.unique_key, provider: nango.integration.provider },
                    ...(connection ? { connection } : {})
                }
            );
            logCtx.attachSpan(new OtlpSpan(logCtx.operation));

            await logCtx.warn(
                `Incoming webhooks for ${scope} are not being verified. Anyone who knows your webhook URL can send events that Nango will process and forward as if they came from ${nango.integration.provider}. ${remediation} to enable verification.`,
                { provider: nango.integration.provider, integration: nango.integration.unique_key, reason }
            );
            await logCtx.success();
        } catch (err) {
            logger.error('failed to log missing webhook secret', { configId: integrationId, err });
        }
    })();
}
