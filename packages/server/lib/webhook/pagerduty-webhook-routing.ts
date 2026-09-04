import crypto from 'node:crypto';

import { NangoError } from '@nangohq/shared';
import { Err, Ok } from '@nangohq/utils';

import { warnMissingWebhookSecret } from './missing-secret.js';
import { safeCompare } from './signature.js';

import type { PagerDutyWebhookPayload, WebhookHandler } from './types.js';
import type { Metadata } from '@nangohq/types';
import type { Result } from '@nangohq/utils';

function verifySignature(secret: string, payload: string, signatures: string): boolean {
    const expected = `v1=${crypto.createHmac('sha256', secret).update(payload).digest('hex')}`;

    return signatures
        .split(',')
        .map((signature) => signature.trim())
        .some((signature) => safeCompare(expected, signature));
}

// PagerDuty generates a new secret per subscription and sends every subscription's signature in the
// header. We enforce a single secret so verification stays cheap.
// https://developer.pagerduty.com/docs/verifying-webhook-signatures
function resolveSecret(webhookSecret: Metadata[string]): Result<string> {
    if (Array.isArray(webhookSecret)) {
        if (webhookSecret.length === 0) {
            return Err(new NangoError('webhook_invalid_secret', { reason: 'No webhook secret configured' }));
        }
        if (webhookSecret.length > 1) {
            return Err(new NangoError('webhook_invalid_secret', { reason: 'Multiple webhook secrets configured. Only one secret is allowed.' }));
        }
        return Ok(webhookSecret[0] as string);
    }

    if (typeof webhookSecret === 'string') {
        return Ok(webhookSecret);
    }

    return Err(new NangoError('webhook_invalid_secret', { reason: 'Invalid webhook secret' }));
}

const route: WebhookHandler<PagerDutyWebhookPayload> = async (nango, headers, body, rawBody) => {
    // https://developer.pagerduty.com/docs/webhooks-overview#custom-headers
    const connectionIdentifierValue = headers['x-nango-connection-id'];

    if (!connectionIdentifierValue) {
        return Err(new NangoError('webhook_missing_nango_connection_id'));
    }

    // Resolve the connection before dispatching so the signature is verified against its secret
    // first. Dispatching to get at the secret would run the customer's scripts on an unverified payload.
    const connection = await nango.getConnectionForWebhook(connectionIdentifierValue);

    if (!connection) {
        return Ok({
            content: { status: 'success' },
            statusCode: 200,
            connectionIds: [],
            toForward: body
        });
    }

    const webhookSecret = connection.metadata?.['webhookSecret'];

    if (webhookSecret) {
        const signatureHeader = headers['x-pagerduty-signature'];
        if (!signatureHeader) {
            return Err(new NangoError('webhook_missing_signature'));
        }

        const secret = resolveSecret(webhookSecret);
        if (secret.isErr()) {
            return Err(secret.error);
        }

        if (!verifySignature(secret.value, rawBody, signatureHeader)) {
            return Err(new NangoError('webhook_invalid_signature'));
        }
    } else {
        warnMissingWebhookSecret(nango, {
            reason: 'pagerduty_missing_webhook_secret',
            secretField: 'webhookSecret connection metadata field',
            scope: connection.connectionId
        });
    }

    const response = await nango.executeScriptForWebhooks({
        body,
        webhookType: 'event.event_type',
        connectionIdentifierValue,
        propName: 'connectionId'
    });

    return Ok({
        content: { status: 'success' },
        statusCode: 200,
        connectionIds: response?.connectionIds || [],
        toForward: body
    });
};

export default route;
