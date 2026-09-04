import { NangoError } from '@nangohq/shared';
import { Err, Ok } from '@nangohq/utils';

import { warnMissingWebhookSecret } from './missing-secret.js';
import { validateSvixSignature } from './signature.js';

import type { FolkWebhookPayload, WebhookHandler } from './types.js';

const route: WebhookHandler<FolkWebhookPayload> = async (nango, headers, body, rawBody, query) => {
    const secret = nango.integration.custom?.['webhookSecret'];

    if (secret) {
        if (validateSvixSignature({ secret, headers, rawBody }) !== 'valid') {
            return Err(new NangoError('webhook_invalid_signature'));
        }
    } else {
        // Folk registers webhooks per connection, so an integration level secret only lines up when the
        // integration has a single connection. Until connection level secrets exist we let these through.
        warnMissingWebhookSecret(nango, { reason: 'folk_missing_webhook_secret', secretField: 'webhook secret' });
    }

    const connectionIdentifierValue = query?.['nangoConnectionId'];

    if (!connectionIdentifierValue) {
        return Err(new NangoError('webhook_missing_connection_id'));
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
