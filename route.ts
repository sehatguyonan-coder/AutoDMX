import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { supabase } from '@/lib/supabase';
import { handleCommentTrigger, handleMessageEvent } from '@/lib/instagram';

async function recordWebhookEvent(
  account: { id: string; user_id: string },
  eventType: string,
  detail: string,
  commentId?: string
) {
  const { error } = await supabase.from('webhook_events').insert({
    user_id: account.user_id,
    account_id: account.id,
    comment_id: commentId || null,
    event_type: eventType,
    detail,
  });

  if (error) console.error('[Webhook POST] Failed to record diagnostic:', error.message);
}

async function recordWebhookFailure(eventType: string, detail: string) {
  const { data: account, error: accountError } = await supabase
    .from('accounts')
    .select('id, user_id')
    .limit(1)
    .maybeSingle();

  if (!account || accountError) {
    console.error('[Webhook POST] Could not identify an account for diagnostic:', accountError?.message);
    return;
  }

  await recordWebhookEvent(account, eventType, detail);
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const mode = searchParams.get('hub.mode');
  const token = searchParams.get('hub.verify_token');
  const challenge = searchParams.get('hub.challenge');

  const verifyToken = process.env.META_VERIFY_TOKEN;

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('[Webhook GET] Verification handshake successful');
    return new Response(challenge, { status: 200 });
  }

  console.warn('[Webhook GET] Verification failed');
  return new Response('Verification token mismatch', { status: 403 });
}

export async function POST(request: NextRequest) {
  const appSecret = process.env.META_APP_SECRET;
  if (!appSecret) {
    await recordWebhookFailure('configuration_error', 'META_APP_SECRET is not configured on the server.');
    return NextResponse.json({ error: 'META_APP_SECRET not configured' }, { status: 500 });
  }

  // 1. Read raw request body
  const rawBody = await request.text();

  // 2. Validate X-Hub-Signature-256 header
  const signatureHeader = request.headers.get('X-Hub-Signature-256');
  if (!signatureHeader) {
    console.warn('[Webhook POST] Missing X-Hub-Signature-256 header');
    await recordWebhookFailure('signature_error', 'Webhook request arrived without the X-Hub-Signature-256 header.');
    return new Response('Missing signature', { status: 403 });
  }

  const [algorithm, signature] = signatureHeader.split('=');
  if (algorithm !== 'sha256' || !signature) {
    console.warn('[Webhook POST] Invalid signature format');
    await recordWebhookFailure('signature_error', 'Webhook request had an invalid X-Hub-Signature-256 format.');
    return new Response('Invalid signature format', { status: 403 });
  }

  const expectedSignature = crypto
    .createHmac('sha256', appSecret)
    .update(rawBody)
    .digest('hex');

  if (signature !== expectedSignature) {
    console.warn('[Webhook POST] Signature mismatch');
    await recordWebhookFailure('signature_error', 'Webhook request arrived, but META_APP_SECRET does not match this Meta app.');
    return new Response('Signature mismatch', { status: 403 });
  }

  // Signature verified! Parse payload.
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    await recordWebhookFailure('payload_error', 'Webhook request arrived with invalid JSON.');
    return NextResponse.json({ error: 'Invalid JSON payload' }, { status: 400 });
  }

  // Check object is "instagram"
  if (payload.object !== 'instagram') {
    return NextResponse.json({ success: true, message: 'Non-instagram event ignored' });
  }

  const entries = payload.entry || [];

  for (const entry of entries) {
    const entryId = entry.id; // Instagram Business Account ID
    if (!entryId) continue;

    // Fetch the single connected account regardless of ID format (single-tenant routing)
    const { data: account, error: accountError } = await supabase
      .from('accounts')
      .select('id, user_id, webhook_account_id, ig_user_id')
      .limit(1)
      .maybeSingle();

    if (accountError || !account) {
      console.warn(`[Webhook POST] No connected account found in database: ${accountError?.message || 'Empty accounts table'}`);
      await recordWebhookFailure('account_error', `Webhook request arrived for account ID ${entryId}, but no connected account was found.`);
      continue;
    }

    // Auto-record the webhook namespace ID if not already set
    if (!account.webhook_account_id) {
      console.log(`[Webhook POST] Storing webhook namespace ID ${entryId} on account ${account.id}`);
      const { error: updateError } = await supabase
        .from('accounts')
        .update({ webhook_account_id: entryId })
        .eq('id', account.id);
      
      if (updateError) {
        console.error(`[Webhook POST] Failed to update webhook_account_id:`, updateError.message);
      }
    }

    // A. Parse and process direct DMs inside entry.messaging
    const messagingList = entry.messaging || [];
    for (const msg of messagingList) {
      const senderId = msg.sender?.id;
      const recipientId = msg.recipient?.id;
      const messageText = msg.message?.text || '';
      if (senderId && recipientId && msg.message) {
        try {
          await handleMessageEvent(senderId, recipientId, messageText);
        } catch (msgErr) {
          console.error('[Webhook POST] handleMessageEvent failed:', msgErr);
        }
      }
    }

    // B. Parse and process comments / messaging events inside entry.changes
    const changes = entry.changes || [];
    for (const change of changes) {
      if (change.field === 'messages') {
        const messageValue = change.value;
        if (messageValue) {
          const senderId = messageValue.sender?.id;
          const recipientId = messageValue.recipient?.id;
          const messageText = messageValue.message?.text || '';
          if (senderId && recipientId) {
            try {
              await handleMessageEvent(senderId, recipientId, messageText);
            } catch (msgErr) {
              console.error('[Webhook POST] handleMessageEvent failed:', msgErr);
            }
          }
        }
        continue;
      }

      if (change.field !== 'comments') continue;

      const commentValue = change.value;
      if (!commentValue || !commentValue.id) continue;

      await recordWebhookEvent(account, 'received', `Comment received: ${commentValue.text || '(empty)'}`, commentValue.id);

      // Bug fix: Skip comments made by our own account to prevent a reply loop.
      // When the bot posts a public reply, Meta fires a webhook for that reply too.
      // Without this guard, the bot replies to its own reply, causing 7-9 repeated comments.
      const commentFromId = commentValue.from?.id;
      if (commentFromId && account.ig_user_id && commentFromId === account.ig_user_id) {
        console.log(`[Webhook POST] Skipping self-comment ${commentValue.id} from our own account to prevent reply loop.`);
        await recordWebhookEvent(account, 'skipped_self', 'Comment was made by the connected Instagram account.', commentValue.id);
        continue;
      }

      const mediaId = commentValue.media?.id;
      const commentText = commentValue.text || '';

      if (!mediaId) {
        await recordWebhookEvent(account, 'skipped_invalid', 'Webhook comment payload did not contain a media ID.', commentValue.id);
        continue;
      }

      // Fetch active comment automations for this account
      const { data: automations, error: automationsError } = await supabase
        .from('automations')
        .select('*')
        .eq('account_id', account.id)
        .eq('is_active', true)
        .eq('trigger_type', 'comment');

      if (automationsError || !automations) {
        console.error('[Webhook POST] Error fetching automations:', automationsError);
        await recordWebhookEvent(account, 'database_error', `Could not fetch automations: ${automationsError?.message || 'unknown error'}`, commentValue.id);
        continue;
      }

      let matchedAutomation = false;
      for (const automation of automations) {
        // Match scope: specific post or any post
        const matchesScope =
          (automation.media_scope === 'specific' && automation.media_id === mediaId) ||
          automation.media_scope === 'any';

        if (!matchesScope) continue;

        // Match keywords: case-insensitive substring or empty keywords list (match all)
        const keywordsList = automation.keywords || [];
        const hasMatchAnyComment = 'match_any_comment' in automation && Boolean((automation as Record<string, unknown>).match_any_comment);

        let matchesKeywords = false;
        if (keywordsList.length === 0 || hasMatchAnyComment) {
          matchesKeywords = true;
        } else {
          matchesKeywords = keywordsList.some((keyword: string) =>
            commentText.toLowerCase().includes(keyword.toLowerCase())
          );
        }

        if (matchesKeywords) {
          matchedAutomation = true;
          // Lock only a comment that is actually about to trigger an automation.
          // Earlier versions inserted this marker before validating the event,
          // permanently discarding a later retry of an incomplete webhook payload.
          const { error: insertError } = await supabase
            .from('processed_comments')
            .insert({ comment_id: commentValue.id });

          if (insertError) {
            if (insertError.code === '23505') {
              console.log(`[Webhook POST] Duplicate comment ${commentValue.id} detected, ignoring.`);
              await recordWebhookEvent(account, 'duplicate', 'This comment was already processed.', commentValue.id);
              break;
            }

            console.error(`[Webhook POST] Database error inserting comment_id ${commentValue.id}:`, insertError);
            return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
          }

          try {
            await handleCommentTrigger(commentValue, automation);
            await recordWebhookEvent(account, 'triggered', `Automation "${automation.name}" was triggered.`, commentValue.id);
          } catch (triggerError) {
            console.error('[Webhook POST] handleCommentTrigger failed:', triggerError);
            await recordWebhookEvent(account, 'trigger_error', triggerError instanceof Error ? triggerError.message : String(triggerError), commentValue.id);
          }
        }
      }

      if (!matchedAutomation) {
        await recordWebhookEvent(account, 'no_match', `No active automation matched post ${mediaId} and comment "${commentText}".`, commentValue.id);
      }
    }
  }

  return NextResponse.json({ success: true });
}
