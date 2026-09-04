import { NangoError } from '@nangohq/shared';
import { Err, getLogger, Ok } from '@nangohq/utils';

import { warnMissingWebhookSecret } from './missing-secret.js';
import { validateHmacSignature } from './signature.js';

import type { NotionWebhook, NotionWebhookVerification, WebhookHandler } from './types.js';

const logger = getLogger('Webhook.Notion');

const route: WebhookHandler<NotionWebhook | NotionWebhookVerification> = async (nango, headers, body, rawBody) => {
    const signature = headers['x-notion-signature'];
    const verificationToken = nango.integration.custom?.['webhookSecret'];

    if ('verification_token' in body) {
        logger.info('Received verification request, skipping signature validation', { configId: nango.integration.id });
    } else if (verificationToken) {
        if (!signature) {
            logger.error('missing signature', { configId: nango.integration.id });
            return Err(new NangoError('webhook_missing_signature'));
        }

        if (!validateHmacSignature({ secret: verificationToken, rawBody, signature, prefix: 'sha256=' })) {
            logger.error('invalid signature', { configId: nango.integration.id });
            return Err(new NangoError('webhook_invalid_signature'));
        }
    } else {
        warnMissingWebhookSecret(nango, { reason: 'notion_missing_verification_token', secretField: 'verification token' });
    }

    const response = await nango.executeScriptForWebhooks({
        body,
        webhookType: 'type',
        connectionIdentifier: 'workspace_id',
        propName: 'workspace_id'
    });

    const connectionIds = response?.connectionIds || [];

    return Ok({
        content: { status: 'success' },
        statusCode: 200,
        connectionIds,
        toForward: body
    });
};

export default route;
