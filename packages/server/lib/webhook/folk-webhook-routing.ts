import { NangoError } from '@nangohq/shared';
import { Err, Ok } from '@nangohq/utils';

import { warnMissingWebhookSecret } from './missing-secret.js';
import { validateSvixSignature } from './signature.js';

import type { FolkWebhookPayload, WebhookHandler } from './types.js';

const route: WebhookHandler<FolkWebhookPayload> = async (nango, headers, body, rawBody, query) => {
    const connectionIdentifierValue = query?.['nangoConnectionId'];

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

    // Folk registers webhooks per connection, so the secret belongs on the connection. The
    // integration level secret stays supported for integrations that only have one connection.
    const connectionSecret = connection.metadata?.['webhookSecret'];

    if (connectionSecret != null && typeof connectionSecret !== 'string') {
        return Err(new NangoError('webhook_invalid_secret', { reason: 'Invalid webhook secret' }));
    }

    const secret = connectionSecret || nango.integration.custom?.['webhookSecret'];

    if (secret) {
        if (validateSvixSignature({ secret, headers, rawBody }) !== 'valid') {
            return Err(new NangoError('webhook_invalid_signature'));
        }
    } else {
        warnMissingWebhookSecret(nango, {
            reason: 'folk_missing_webhook_secret',
            remediation: 'Set webhookSecret in the connection metadata',
            connection: { id: connection.id, name: connection.connectionId }
        });
    }

    const response = await nango.executeScriptForWebhooks({
        body,
        webhookType: 'type',
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
