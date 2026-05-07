#!/usr/bin/env node
/**
 * Installs the guardrails hooks into the user-level Claude Code settings
 * (~/.claude/settings.json), so they activate in every project — not just
 * inside this repo. Re-running is safe; it updates existing entries in place.
 *
 * Uninstall: pass --uninstall to remove guardrails entries from the user config.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const PRE_HOOK = path.join(PROJECT_ROOT, 'hooks', 'pre-tool-use.js');
const POST_HOOK = path.join(PROJECT_ROOT, 'hooks', 'post-tool-use.js');

const HOME = os.homedir();
const USER_SETTINGS_DIR = path.join(HOME, '.claude');
const USER_SETTINGS_FILE = path.join(USER_SETTINGS_DIR, 'settings.json');

const uninstall = process.argv.includes('--uninstall');

function readSettings() {
  if (!fs.existsSync(USER_SETTINGS_FILE)) return {};
  try {
    return JSON.parse(fs.readFileSync(USER_SETTINGS_FILE, 'utf-8'));
  } catch {
    console.warn(`! Could not parse ${USER_SETTINGS_FILE}, aborting to avoid clobbering it.`);
    process.exit(1);
  }
}

function isGuardrailsEntry(entry, scriptName) {
  return entry.hooks && entry.hooks.some(h => h.command && h.command.includes(scriptName));
}

function upsertHook(list, matcher, scriptPath, scriptName) {
  const idx = list.findIndex(e => isGuardrailsEntry(e, scriptName));
  const entry = {
    matcher,
    hooks: [{ type: 'command', command: `node ${scriptPath}` }],
  };
  if (idx >= 0) {
    list[idx] = entry;
    return 'updated';
  }
  list.push(entry);
  return 'installed';
}

function removeHook(list, scriptName) {
  const before = list.length;
  const filtered = list.filter(e => !isGuardrailsEntry(e, scriptName));
  return { list: filtered, removed: before - filtered.length };
}

function main() {
  if (!fs.existsSync(USER_SETTINGS_DIR)) {
    fs.mkdirSync(USER_SETTINGS_DIR, { recursive: true });
  }

  const settings = readSettings();
  settings.hooks = settings.hooks || {};
  settings.hooks.PreToolUse = settings.hooks.PreToolUse || [];
  settings.hooks.PostToolUse = settings.hooks.PostToolUse || [];

  if (uninstall) {
    const pre = removeHook(settings.hooks.PreToolUse, 'pre-tool-use.js');
    const post = removeHook(settings.hooks.PostToolUse, 'post-tool-use.js');
    settings.hooks.PreToolUse = pre.list;
    settings.hooks.PostToolUse = post.list;
    fs.writeFileSync(USER_SETTINGS_FILE, JSON.stringify(settings, null, 2));
    console.log(`- Removed ${pre.removed} PreToolUse and ${post.removed} PostToolUse guardrails entr(ies) from ${USER_SETTINGS_FILE}`);
    return;
  }

  const preStatus = upsertHook(settings.hooks.PreToolUse, 'Write|Edit|Bash', PRE_HOOK, 'pre-tool-use.js');
  const postStatus = upsertHook(settings.hooks.PostToolUse, 'Write|Edit', POST_HOOK, 'post-tool-use.js');

  fs.writeFileSync(USER_SETTINGS_FILE, JSON.stringify(settings, null, 2));

  console.log(`+ PreToolUse  ${preStatus}`);
  console.log(`+ PostToolUse ${postStatus}`);
  console.log(`  Config: ${USER_SETTINGS_FILE}`);
  console.log('\nGuardrails are now active in every project Claude Code opens.');
  console.log('Tune severity with the GUARDRAILS_LEVEL env var (critical | high | strict). Default: high.');
  console.log('Uninstall: npm run install-globally -- --uninstall');
}

main();
