/**
 * Copyright (c) Forward Email LLC
 * SPDX-License-Identifier: BUSL-1.1
 */

const { readFileSync } = require('node:fs');
const process = require('node:process');

const apn = require('@parse/node-apn');
const { GoogleAuth } = require('google-auth-library');
const ms = require('ms');
const pMap = require('p-map');
const revHash = require('rev-hash');
const webPush = require('web-push');

const PushTokens = require('#models/push-tokens');
const config = require('#config');
const { isPrivateHostResolved } = require('#helpers/is-private-host');
const logger = require('#helpers/logger');
const safeFetch = require('#helpers/safe-fetch');

//
// Push notification delivery helper for the Forward Email Mail App.
//
// This module delivers "alert"-style push notifications to registered
// mobile/desktop devices when a WebSocket event occurs and the target
// alias has no active WebSocket connection (i.e. the app is backgrounded
// or closed).
//
// Architecture:
//   1. `sendWebSocketNotification` publishes to Redis pub/sub.
//   2. The WS handler delivers to connected clients.
//   3. For aliases with NO connected WS clients, the WS handler calls
//      `sendPushNotification` (this module) as a fallback to wake the app.
//
// Delivery transports:
//   * APNs  — via token-based auth (.p8 key) with pushType='alert'.
//   * FCM   — via Firebase Admin SDK HTTP v1 API.
//   * UnifiedPush — RFC 8291 encrypted Web Push to the distributor endpoint.
//   * Web Push — reserved for browser PushSubscription delivery.
//
// Rate limiting:
//   One push per (alias, event) per 30 seconds via Redis to coalesce
//   rapid-fire mutations (e.g. bulk IMAP STORE) into a single wake-up.
//
// Safety:
//   If env vars are not configured for a given platform, delivery is
//   silently skipped (no-op). This ensures the server runs cleanly in
//   development or environments where push is not yet set up.
//

const PUSH_COALESCE_MS = ms('30s');
const PUSH_CONCURRENCY = 5;

/**
 * Validate a URL is safe for outbound fetch (not SSRF).
 * Uses isPrivateHostResolved which:
 *   - Checks hostname against REGEX_LOCALHOST (RFC 1918, loopback, link-local, etc.)
 *   - Checks against config.testDomains (reserved TLDs, cloud metadata hostnames)
 *   - Resolves the hostname via DNS and checks all returned IPs
 *   - Prevents DNS rebinding attacks (attacker changes A record after registration)
 *
 * This matches the pattern used by domain-connect, on-data-mx, process-email,
 * and wkd helpers — all of which resolve DNS before making outbound requests.
 *
 * @param {string} urlString - The URL to validate
 * @param {object} [resolver] - Optional Tangerine resolver instance (Redis-backed, cached)
 * @returns {Promise<void>}
 * @throws {Error} if URL targets private/reserved addresses
 */
async function validateOutboundUrl(urlString, resolver) {
  const parsed = new URL(urlString);

  if (parsed.protocol !== 'https:') {
    throw new Error('Only HTTPS URLs are allowed for push delivery');
  }

  // Use isPrivateHostResolved (async DNS resolution) to prevent DNS rebinding.
  // This matches the pattern in domain-connect.js, on-data-mx.js, process-email.js, wkd.js
  if (await isPrivateHostResolved(parsed.hostname, resolver)) {
    throw new Error(
      `Push endpoint targets private/reserved address: ${parsed.hostname}`
    );
  }

  if (parsed.username || parsed.password) {
    throw new Error('Push endpoint must not contain credentials');
  }
}

/**
 * Returns true if APNs is configured and ready to deliver.
 */
function isApnsConfigured() {
  const keyPath =
    config.pushNotifications?.apnsKeyPath || process.env.APNS_KEY_PATH;
  const keyId = config.pushNotifications?.apnsKeyId || process.env.APNS_KEY_ID;
  const teamId =
    config.pushNotifications?.apnsTeamId || process.env.APNS_TEAM_ID;
  return Boolean(keyPath && keyId && teamId);
}

/**
 * Returns true if FCM is configured and ready to deliver.
 */
function isFcmConfigured() {
  const projectId =
    config.pushNotifications?.fcmProjectId || process.env.FCM_PROJECT_ID;
  const serviceAccountPath =
    config.pushNotifications?.fcmServiceAccountPath ||
    process.env.FCM_SERVICE_ACCOUNT_PATH;
  return Boolean(projectId && serviceAccountPath);
}

/**
 * Returns true if the matching UnifiedPush VAPID key pair is configured.
 */
function isVapidConfigured() {
  const subject =
    config.pushNotifications?.vapidSubject || process.env.VAPID_SUBJECT;
  const publicKey =
    config.pushNotifications?.vapidPublicKey || process.env.VAPID_PUBLIC_KEY;
  const privateKey =
    config.pushNotifications?.vapidPrivateKey || process.env.VAPID_PRIVATE_KEY;
  return Boolean(subject && publicKey && privateKey);
}

function getVapidDetails() {
  return {
    subject:
      config.pushNotifications?.vapidSubject || process.env.VAPID_SUBJECT,
    publicKey:
      config.pushNotifications?.vapidPublicKey || process.env.VAPID_PUBLIC_KEY,
    privateKey:
      config.pushNotifications?.vapidPrivateKey || process.env.VAPID_PRIVATE_KEY
  };
}

function createPermanentPushError(message, cause) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.isPermanentPushFailure = true;
  return error;
}

// Cached APNs provider (reused across requests to avoid connection churn)
let _apnsProvider = null;
let _apnsProviderConfig = null;

/**
 * Get or create a cached APNs provider instance.
 * Recreated if configuration changes.
 */
function getApnsProvider() {
  const keyPath =
    config.pushNotifications?.apnsKeyPath || process.env.APNS_KEY_PATH;
  const keyId = config.pushNotifications?.apnsKeyId || process.env.APNS_KEY_ID;
  const teamId =
    config.pushNotifications?.apnsTeamId || process.env.APNS_TEAM_ID;
  const production = config.pushNotifications?.apnsProduction !== false;

  const configKey = `${keyPath}:${keyId}:${teamId}:${production}`;

  if (_apnsProvider && _apnsProviderConfig === configKey) {
    return _apnsProvider;
  }

  // Validate the key file exists and is readable before creating provider
  try {
    readFileSync(keyPath);
  } catch (err) {
    throw new Error(`APNs key file not readable at ${keyPath}: ${err.message}`);
  }

  if (_apnsProvider) {
    _apnsProvider.shutdown();
  }

  _apnsProvider = new apn.Provider({
    token: { key: keyPath, keyId, teamId },
    production
  });
  _apnsProviderConfig = configKey;

  return _apnsProvider;
}

/**
 * Send a push notification to all registered devices for an alias.
 *
 * @param {Object} client - Redis client instance
 * @param {string} aliasId - The alias ID to notify
 * @param {string} event - The WebSocket event name (e.g. 'newMessage')
 * @param {Object} [data={}] - Event payload (title, body, etc.)
 * @param {object} [resolver] - Optional Tangerine resolver instance
 */
// eslint-disable-next-line max-params
async function sendPushNotification(
  client,
  aliasId,
  event,
  data = {},
  resolver
) {
  if (!client || !aliasId || !event) return;

  // Sanitize event name: only allow known safe characters
  if (typeof event !== 'string' || !/^[a-zA-Z]{1,64}$/.test(event)) return;

  try {
    // Rate-limit: one push per (alias, event) per PUSH_COALESCE_MS
    const cacheKey = `push_notify:${revHash(aliasId.toString())}:${revHash(
      event
    )}`;
    const cached = await client.get(cacheKey);
    if (cached) return;
    await client.set(cacheKey, '1', 'PX', PUSH_COALESCE_MS);

    // Find all active tokens for this alias
    const tokens = await PushTokens.findActiveForAlias(aliasId);
    if (!tokens || tokens.length === 0) return;

    // Build the notification payload
    const payload = buildPayload(event, data);

    await pMap(
      tokens,
      async (tokenDoc) => {
        try {
          await deliverToToken(tokenDoc, payload, resolver);
          await PushTokens.recordSuccess(tokenDoc._id);
        } catch (err) {
          logger.warn('Push delivery failed', {
            token_id: tokenDoc._id,
            platform: tokenDoc.platform,
            error: err.message
          });
          await (err.isPermanentPushFailure
            ? PushTokens.deleteOne({ _id: tokenDoc._id }).exec()
            : PushTokens.recordFailure(tokenDoc._id));
        }
      },
      { concurrency: PUSH_CONCURRENCY }
    );
  } catch (err) {
    logger.fatal(err, { aliasId, event });
  }
}

/**
 * Build a platform-agnostic notification payload from the WS event.
 * Sanitizes all string fields to prevent injection.
 */
function buildPayload(event, data) {
  // Map WS events to human-readable notification content
  const TITLES = {
    newMessage: 'New Email',
    messagesMoved: 'Messages Moved',
    messagesCopied: 'Messages Copied',
    flagsUpdated: 'Flags Updated',
    messagesExpunged: 'Messages Deleted',
    mailboxCreated: 'Mailbox Created',
    mailboxDeleted: 'Mailbox Deleted',
    mailboxRenamed: 'Mailbox Renamed',
    calendarCreated: 'Calendar Created',
    calendarUpdated: 'Calendar Updated',
    calendarDeleted: 'Calendar Deleted',
    calendarEventCreated: 'New Calendar Event',
    calendarEventUpdated: 'Calendar Event Updated',
    calendarEventDeleted: 'Calendar Event Deleted',
    contactCreated: 'New Contact',
    contactUpdated: 'Contact Updated',
    contactDeleted: 'Contact Deleted',
    addressBookCreated: 'Address Book Created',
    addressBookDeleted: 'Address Book Deleted',
    newRelease: 'App Update Available'
  };

  // Use only known titles; fallback to generic
  const title = TITLES[event] || 'Forward Email';

  // Sanitize body: truncate to prevent oversized payloads
  const MAX_BODY_LENGTH = 256;
  const bodySource = [data.body, data.subject, data.name].find(
    (value) => typeof value === 'string'
  );
  const body =
    typeof bodySource === 'string'
      ? bodySource.slice(0, MAX_BODY_LENGTH)
      : `You have a new ${event} event`;

  // Sanitize data fields: only include known safe identifiers
  const safeAliasId =
    typeof data.aliasId === 'string' || typeof data.alias_id === 'string'
      ? String(data.aliasId || data.alias_id).slice(0, 64)
      : '';
  const safeMessageId =
    typeof data.message_id === 'string' || typeof data.id === 'string'
      ? String(data.message_id || data.id).slice(0, 255)
      : '';
  const safeMailbox =
    typeof data.mailbox === 'string' || typeof data.path === 'string'
      ? String(data.mailbox || data.path).slice(0, 255)
      : '';

  return {
    title,
    body,
    event,
    data: {
      event,
      alias_id: safeAliasId,
      message_id: safeMessageId,
      mailbox: safeMailbox
    }
  };
}

/**
 * Deliver a notification to a specific token based on its platform.
 */
async function deliverToToken(tokenDoc, payload, resolver) {
  switch (tokenDoc.platform) {
    case 'apns': {
      return deliverApns(tokenDoc, payload);
    }

    case 'fcm': {
      return deliverFcm(tokenDoc, payload);
    }

    case 'unified-push': {
      return deliverUnifiedPush(tokenDoc, payload, resolver);
    }

    case 'web-push': {
      return deliverWebPush(tokenDoc);
    }

    default: {
      throw new Error(`Unsupported platform: ${tokenDoc.platform}`);
    }
  }
}

/**
 * APNs delivery via HTTP/2.
 *
 * Uses token-based auth (.p8 key) with pushType='alert' and priority=10
 * for user-visible notifications.
 * The topic is the mail app's bundle ID (not the DAV cert topic).
 *
 * If APNs env vars are not configured, this is a silent no-op.
 */
async function deliverApns(tokenDoc, payload) {
  if (!isApnsConfigured()) {
    logger.debug('APNs not configured, skipping push delivery');
    return;
  }

  const provider = getApnsProvider();
  const bundleId =
    config.pushNotifications?.apnsBundleId ||
    process.env.APNS_BUNDLE_ID ||
    'net.forwardemail.mail';

  const note = new apn.Notification();
  note.pushType = 'alert';
  note.topic = bundleId;
  note.expiry = Math.floor(Date.now() / 1000) + 86400; // 24 hours
  note.priority = 10;
  note.alert = {
    title: String(payload.title).slice(0, 128),
    body: String(payload.body).slice(0, 256)
  };
  note.payload = payload.data;
  note.sound = 'default';

  const result = await provider.send(note, tokenDoc.token);

  if (result.failed && result.failed.length > 0) {
    const failure = result.failed[0];
    // 410 Gone = token is no longer valid
    if (Number.parseInt(failure.status, 10) === 410) {
      throw new Error('APNs token expired (410 Gone)');
    }

    throw new Error(
      `APNs delivery failed: ${failure.response?.reason || failure.status}`
    );
  }
}

/**
 * FCM delivery via Firebase Admin SDK HTTP v1 API.
 *
 * Uses service account credentials for authentication.
 * Sends a data+notification message for maximum compatibility.
 *
 * If FCM env vars are not configured, this is a silent no-op.
 */
async function deliverFcm(tokenDoc, payload) {
  if (!isFcmConfigured()) {
    logger.debug('FCM not configured, skipping push delivery');
    return;
  }

  const projectId =
    config.pushNotifications?.fcmProjectId || process.env.FCM_PROJECT_ID;
  const serviceAccountPath =
    config.pushNotifications?.fcmServiceAccountPath ||
    process.env.FCM_SERVICE_ACCOUNT_PATH;

  // Validate projectId format to prevent URL injection
  if (!/^[a-z][a-z\d-]{4,28}[a-z\d]$/.test(projectId)) {
    throw new Error('Invalid FCM project ID format');
  }

  const auth = new GoogleAuth({
    keyFile: serviceAccountPath,
    scopes: ['https://www.googleapis.com/auth/firebase.messaging']
  });

  const accessToken = await auth.getAccessToken();

  const message = {
    message: {
      token: tokenDoc.token,
      notification: {
        title: String(payload.title).slice(0, 128),
        body: String(payload.body).slice(0, 256)
      },
      data: Object.fromEntries(
        Object.entries(payload.data).map(([k, v]) => [
          String(k).slice(0, 64),
          String(v).slice(0, 255)
        ])
      ),
      android: {
        priority: 'high',
        notification: { channel_id: 'mail_notifications' }
      }
    }
  };

  const fcmUrl = `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(
    projectId
  )}/messages:send`;

  const response = await fetch(fcmUrl, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(message)
  });

  if (!response.ok) {
    const responseBody = await response.text();
    // 404 = token not found (unregistered)
    if (response.status === 404) {
      throw new Error('FCM token not registered (404)');
    }

    throw new Error(
      `FCM delivery failed (${response.status}): ${responseBody.slice(0, 200)}`
    );
  }
}

/**
 * Parse the canonical RFC 8291 subscription stored for UnifiedPush.
 * Legacy endpoint-only records are intentionally treated as permanently
 * invalid because they do not contain the client key material required to
 * encrypt a payload.
 */
function parseUnifiedPushSubscription(token) {
  let subscription;
  try {
    subscription = JSON.parse(token);
  } catch (err) {
    throw createPermanentPushError(
      'UnifiedPush subscription is not valid JSON',
      err
    );
  }

  if (
    !subscription ||
    typeof subscription.endpoint !== 'string' ||
    !subscription.keys ||
    typeof subscription.keys.p256dh !== 'string' ||
    typeof subscription.keys.auth !== 'string'
  ) {
    throw createPermanentPushError('UnifiedPush subscription is incomplete');
  }

  return {
    endpoint: subscription.endpoint,
    keys: {
      p256dh: subscription.keys.p256dh,
      auth: subscription.keys.auth
    }
  };
}

/**
 * Deliver an RFC 8291 encrypted payload to a UnifiedPush distributor.
 *
 * Android's UnifiedPush connector decrypts the aes128gcm content before the
 * application callback receives it. VAPID binds delivery to the application
 * server key whose public half was supplied during connector registration.
 * The encrypted request is sent through safeFetch so DNS is resolved once,
 * validated, and pinned to the outbound connection.
 */
async function deliverUnifiedPush(
  tokenDoc,
  payload,
  resolver,
  {
    generateRequestDetails = webPush.generateRequestDetails,
    fetch = safeFetch
  } = {}
) {
  if (!isVapidConfigured()) {
    logger.debug('VAPID not configured, skipping UnifiedPush delivery');
    return;
  }

  const subscription = parseUnifiedPushSubscription(tokenDoc.token);
  const parsed = new URL(subscription.endpoint);
  if (parsed.protocol !== 'https:') {
    throw createPermanentPushError(
      'Only HTTPS URLs are allowed for push delivery'
    );
  }

  if (parsed.username || parsed.password) {
    throw createPermanentPushError(
      'Push endpoint must not contain credentials'
    );
  }

  const body = JSON.stringify({
    event: payload.event,
    title: payload.title,
    body: payload.body,
    ...payload.data
  });

  try {
    const request = generateRequestDetails(subscription, body, {
      TTL: 60,
      urgency: 'high',
      contentEncoding: 'aes128gcm',
      vapidDetails: getVapidDetails()
    });
    const response = await fetch(request.endpoint, {
      method: request.method,
      headers: request.headers,
      body: request.body,
      bodyTimeout: 10_000,
      headersTimeout: 10_000,
      resolver
    });
    const responseBody = await response.body.text();

    if (response.statusCode < 200 || response.statusCode >= 300) {
      const error = new Error('UnifiedPush endpoint returned an error');
      error.statusCode = response.statusCode;
      error.body = responseBody;
      throw error;
    }

    return { statusCode: response.statusCode };
  } catch (err) {
    const statusCode = Number(err.statusCode);
    const details =
      typeof err.body === 'string' && err.body
        ? `: ${err.body.slice(0, 200)}`
        : '';
    const message = `UnifiedPush delivery failed (${
      statusCode || 'network'
    })${details}`;

    // RFC 8030: 404/410 mean the subscription is no longer valid and must not
    // be retried. Other statuses retain the normal consecutive-failure policy.
    if (statusCode === 404 || statusCode === 410) {
      throw createPermanentPushError(message, err);
    }

    throw new Error(message, { cause: err });
  }
}

/**
 * Web Push delivery (placeholder for future implementation).
 * Silent no-op until web-push is integrated.
 */

async function deliverWebPush(tokenDoc) {
  // TODO: implement web-push delivery using the web-push npm package
  logger.info('Web Push delivery not yet implemented', {
    token_id: tokenDoc._id
  });
}

module.exports = sendPushNotification;
module.exports.sendPushNotification = sendPushNotification;
module.exports._test = {
  buildPayload,
  deliverToToken,
  deliverApns,
  deliverFcm,
  deliverUnifiedPush,
  deliverWebPush,
  parseUnifiedPushSubscription,
  isApnsConfigured,
  isFcmConfigured,
  isVapidConfigured,
  getVapidDetails,
  validateOutboundUrl
};
