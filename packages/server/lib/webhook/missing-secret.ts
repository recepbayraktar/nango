import { OtlpSpan } from '@nangohq/logs';
import { getLogger, metrics } from '@nangohq/utils';

import type { InternalNango } from './internal-nango.js';

const logger = getLogger('Webhook.MissingSecret');

/**
 * One warning per integration per window. Incoming webhook volume is high enough that a
 * log operation per request would flood the customer's logs and our storage, and the
 * warning says the same thing every time.
 */
const WARN_INTERVAL_MS = 60 * 60 * 1000;
const lastWarnedAt = new Map<number, number>();

function shouldWarn(integrationId: number): boolean {
    const now = Date.now();
    const previous = lastWarnedAt.get(integrationId);

    if (previous && now - previous < WARN_INTERVAL_MS) {
        return false;
    }

    lastWarnedAt.set(integrationId, now);
    return true;
}

/**
 * Surface a skipped signature check in the customer's own logs.
 *
 * Our posture when a provider supports signature verification but no webhook secret is
 * configured is to let the webhook through, so the only signal the customer gets that
 * their traffic is unverified is this warning.
 */
export function warnMissingWebhookSecret(nango: InternalNango, { reason, secretField }: { reason: string; secretField: string }): void {
    const integrationId = nango.integration.id;

    metrics.increment(metrics.Types.WEBHOOK_INCOMING_UNVERIFIED, 1, {
        provider: nango.integration.provider,
        reason
    });

    if (!integrationId || !shouldWarn(integrationId)) {
        return;
    }

    void (async () => {
        try {
            const logCtx = await nango.logContextGetter.create(
                { operation: { type: 'webhook', action: 'incoming' }, expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString() },
                {
                    account: nango.team,
                    environment: nango.environment,
                    integration: { id: integrationId, name: nango.integration.unique_key, provider: nango.integration.provider }
                }
            );
            logCtx.attachSpan(new OtlpSpan(logCtx.operation));

            await logCtx.warn(
                `Incoming webhooks for this integration are not being verified because no ${secretField} is configured. Anyone who knows your webhook URL can send events that Nango will process and forward as if they came from ${nango.integration.provider}. Set the webhook secret on the integration to enable signature verification.`,
                { provider: nango.integration.provider, integration: nango.integration.unique_key, reason }
            );
            await logCtx.success();
        } catch (err) {
            logger.error('failed to log missing webhook secret', { configId: integrationId, err });
        }
    })();
}
