import { beforeEach, describe, expect, it, vi } from 'vitest';

import { logContextGetter } from '@nangohq/logs';
import { seeders } from '@nangohq/shared';
import { getTestConfig } from '@nangohq/shared/lib/seeders/config.seeder.js';

import { InternalNango } from './internal-nango.js';
import { warnMissingWebhookSecret } from './missing-secret.js';

function nangoFor(integrationId: number): InternalNango {
    const integration = getTestConfig({ provider: 'folk' });
    integration.id = integrationId;

    return new InternalNango({
        team: seeders.getTestTeam(),
        environment: seeders.getTestEnvironment(),
        plan: seeders.getTestPlan(),
        integration,
        logContextGetter
    });
}

/** The warning is fire and forget, so wait for the queued microtasks to settle. */
async function settle() {
    await new Promise((resolve) => setImmediate(resolve));
}

describe('warnMissingWebhookSecret', () => {
    let create: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        vi.restoreAllMocks();
        create = vi.spyOn(logContextGetter, 'create').mockResolvedValue({
            attachSpan: vi.fn(),
            warn: vi.fn().mockResolvedValue(true),
            success: vi.fn().mockResolvedValue(undefined)
        } as any);
    });

    it('writes a warning to the operation logs', async () => {
        warnMissingWebhookSecret(nangoFor(4001), { reason: 'folk_missing_webhook_secret' });
        await settle();

        expect(create).toHaveBeenCalledTimes(1);
        const [operation] = create.mock.calls[0]!;
        expect(operation).toMatchObject({ operation: { type: 'webhook', action: 'incoming' } });
    });

    it('uses the default remediation when none is given', async () => {
        const nango = nangoFor(4002);
        warnMissingWebhookSecret(nango, { reason: 'folk_missing_webhook_secret' });
        await settle();

        const logCtx = await create.mock.results[0]!.value;
        expect(logCtx.warn.mock.calls[0][0]).toContain('Set the webhook secret on the integration to enable verification');
        expect(logCtx.warn.mock.calls[0][0]).toContain('Incoming webhooks for this integration');
    });

    it('uses the remediation it is given', async () => {
        warnMissingWebhookSecret(nangoFor(4003), {
            reason: 'folk_missing_webhook_secret',
            remediation: 'Set webhookSecret in the connection metadata'
        });
        await settle();

        const logCtx = await create.mock.results[0]!.value;
        expect(logCtx.warn.mock.calls[0][0]).toContain('Set webhookSecret in the connection metadata to enable verification');
    });

    it('attaches the connection and says so when one is given', async () => {
        warnMissingWebhookSecret(nangoFor(4004), {
            reason: 'folk_missing_webhook_secret',
            connection: { id: 77, name: 'conn-a' }
        });
        await settle();

        const [, additional] = create.mock.calls[0]!;
        expect(additional).toMatchObject({ connection: { id: 77, name: 'conn-a' } });

        const logCtx = await create.mock.results[0]!.value;
        expect(logCtx.warn.mock.calls[0][0]).toContain('Incoming webhooks for this connection');
    });

    it('throttles repeat warnings for the same integration', async () => {
        const nango = nangoFor(4005);

        warnMissingWebhookSecret(nango, { reason: 'folk_missing_webhook_secret' });
        warnMissingWebhookSecret(nango, { reason: 'folk_missing_webhook_secret' });
        await settle();

        expect(create).toHaveBeenCalledTimes(1);
    });

    it('warns once per connection rather than once per integration', async () => {
        const nango = nangoFor(4006);

        warnMissingWebhookSecret(nango, { reason: 'folk_missing_webhook_secret', connection: { id: 1, name: 'conn-a' } });
        warnMissingWebhookSecret(nango, { reason: 'folk_missing_webhook_secret', connection: { id: 2, name: 'conn-b' } });
        warnMissingWebhookSecret(nango, { reason: 'folk_missing_webhook_secret', connection: { id: 1, name: 'conn-a' } });
        await settle();

        expect(create).toHaveBeenCalledTimes(2);
    });

    it('does not throw when the log write fails', async () => {
        create.mockRejectedValue(new Error('logs are down'));

        expect(() => warnMissingWebhookSecret(nangoFor(4007), { reason: 'folk_missing_webhook_secret' })).not.toThrow();
        await settle();
    });
});
