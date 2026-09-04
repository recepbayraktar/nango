import { NangoError } from '@nangohq/shared';
import { Err, getLogger, Ok } from '@nangohq/utils';

import { warnMissingWebhookSecret } from './missing-secret.js';
import { safeCompare, validateSvixSignature } from './signature.js';

import type { WebhookHandler } from './types.js';

const logger = getLogger('Webhook.Gitlab');

function getBodyConnectionId(body: unknown): string | undefined {
    if (!body || typeof body !== 'object' || !('nangoConnectionId' in body)) {
        return undefined;
    }

    const connectionId = body.nangoConnectionId;
    return typeof connectionId === 'string' ? connectionId : undefined;
}

const route: WebhookHandler = async (nango, headers, body, rawBody, query) => {
    // GitLab payloads carry no Nango connection id, so route by the nangoConnectionId query param on the webhook URL.
    const connectionIdentifierValue = query?.['nangoConnectionId'] ?? getBodyConnectionId(body);

    if (!connectionIdentifierValue) {
        return Err(new NangoError('webhook_missing_connection_id'));
    }

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
    if (webhookSecret != null && typeof webhookSecret !== 'string') {
        return Err(new NangoError('webhook_invalid_secret', { reason: 'Invalid webhook secret' }));
    }

    if (webhookSecret) {
        const signature = headers['webhook-signature'];
        const legacyToken = headers['x-gitlab-token'];
        const valid = signature
            ? validateSvixSignature({ secret: webhookSecret, headers, rawBody }) === 'valid'
            : Boolean(legacyToken && safeCompare(webhookSecret, legacyToken));

        if (!valid) {
            logger.error('invalid signature', { configId: nango.integration.id, connectionId: connection.connectionId });
            return Err(new NangoError(signature || legacyToken ? 'webhook_invalid_signature' : 'webhook_missing_signature'));
        }
    } else {
        warnMissingWebhookSecret(nango, {
            reason: 'gitlab_missing_webhook_secret',
            secretField: 'webhookSecret connection metadata field',
            scope: connection.connectionId
        });
    }

    const response = await nango.executeScriptForWebhooks({
        body,
        webhookHeaderValue: headers['x-gitlab-event'] as string,
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
