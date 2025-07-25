/**
 * Copyright (c) Forward Email LLC
 * SPDX-License-Identifier: BUSL-1.1
 */

const users = require('./users');
const domains = require('./domains');
const dashboard = require('./dashboard');
const logs = require('./logs');
const allowlist = require('./allowlist');
const denylist = require('./denylist');
const emails = require('./emails');
const inquiries = require('./inquiries');
const payments = require('./payments');

module.exports = {
  dashboard,
  users,
  domains,
  logs,
  allowlist,
  denylist,
  emails,
  inquiries,
  payments
};
