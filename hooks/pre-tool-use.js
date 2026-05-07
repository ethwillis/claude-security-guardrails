#!/usr/bin/env node
/**
 * Claude Code PreToolUse Hook - BLOCKING security scanner + command guard
 *
 * Handles TWO types of tool calls:
 *   Write/Edit → Scans proposed content for secrets, vulnerabilities, insecure patterns
 *   Bash       → Checks command against dangerous patterns (rm -rf, force push, etc.)
 *
 * SAFETY_LEVEL: 'critical' | 'high' | 'strict'
 *   critical - Only block catastrophic: leaked secrets, eval(), rm -rf /, fork bombs
 *   high     - + block: XSS, SQL injection, force push main, git reset --hard, chmod 777
 *   strict   - + block: all warnings, any force push, sudo rm, docker prune
 *
 * Response protocol:
 *   console.log('{}')                              → allow the tool call
 *   console.log(JSON.stringify({                   → BLOCK the tool call
 *     hookSpecificOutput: {
 *       hookEventName: 'PreToolUse',
 *       permissionDecision: 'deny',
 *       permissionDecisionReason: '...'
 *     }
 *   }))
 *
 * Setup in .claude/settings.json:
 * {
 *   "hooks": {
 *     "PreToolUse": [{
 *       "matcher": "Write|Edit|Bash",
 *       "hooks": [{ "type": "command", "command": "node /path/to/pre-tool-use.js" }]
 *     }]
 *   }
 * }
 */

const fs = require('fs');
const path = require('path');
const { scanSecrets } = require('../scanner/scanners/secrets');
const { scanOwasp } = require('../scanner/scanners/owasp');
const { scanCodePatterns } = require('../scanner/scanners/codePatterns');
const { checkCommand } = require('../scanner/scanners/dangerousCommands');
const { SEVERITY } = require('../scanner/utils/severity');
const { appendEvent } = require('../scanner/utils/activityLog');

const LEVELS = { critical: 1, high: 2, strict: 3 };
const RAW_LEVEL = (process.env.GUARDRAILS_LEVEL || 'high').toLowerCase();
const SAFETY_LEVEL = LEVELS[RAW_LEVEL] ? RAW_LEVEL : 'high';
const LOG_DIR = path.join(process.env.HOME, '.claude', 'hooks-logs');

function fileLog(data) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    const file = path.join(LOG_DIR, `${new Date().toISOString().slice(0, 10)}.jsonl`);
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), hook: 'security-scanner-pre', ...data }) + '\n');
  } catch {}
}

function shouldBlock(severity) {
  const threshold = LEVELS[SAFETY_LEVEL] || 2;
  const severityLevel = {
    [SEVERITY.CRITICAL]: LEVELS.critical,
    [SEVERITY.HIGH]: LEVELS.high,
    [SEVERITY.MEDIUM]: LEVELS.strict,
    [SEVERITY.LOW]: LEVELS.strict,
  };
  return (severityLevel[severity] || 99) <= threshold;
}

function deny(reason) {
  console.log(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    }
  }));
}

function allow() {
  console.log('{}');
}

// ── Handle Bash commands ──
function handleBash(data) {
  const command = data.tool_input?.command || '';
  if (!command) return allow();

  const result = checkCommand(command, SAFETY_LEVEL);

  if (result.blocked) {
    const p = result.pattern;
    const emoji = p.level === 'critical' ? '🚨' : p.level === 'high' ? '⛔' : '⚠️';

    fileLog({ level: 'BLOCKED', type: 'bash', id: p.id, priority: p.level, command: command.substring(0, 200), session_id: data.session_id });

    // Log to dashboard
    appendEvent({
      action: 'blocked',
      hook: 'PreToolUse',
      tool: 'Bash',
      target: command.substring(0, 200),
      reason: p.reason,
      severity: p.level,
      patternId: p.id,
    });

    deny(`${emoji} [${p.id}] Dangerous command blocked: ${p.reason}\n\nCommand: ${command.substring(0, 150)}\n\nThis command was blocked because it could cause irreversible damage.\nIf you really need to run this, do it manually in your terminal.`);
  } else {
    fileLog({ level: 'ALLOWED', type: 'bash', command: command.substring(0, 200), session_id: data.session_id });

    appendEvent({
      action: 'allowed',
      hook: 'PreToolUse',
      tool: 'Bash',
      target: command.substring(0, 200),
    });

    allow();
  }
}

// ── Handle Write/Edit ──
function handleWriteEdit(data) {
  const content = data.tool_input?.content || data.tool_input?.new_string || '';
  const filePath = data.tool_input?.file_path || 'unknown';

  if (!content) {
    appendEvent({ action: 'allowed', hook: 'PreToolUse', tool: data.tool_name, target: filePath });
    return allow();
  }

  // Run scanners on the proposed content
  const findings = [
    ...scanSecrets(content, filePath),
    ...scanOwasp(content, filePath),
    ...scanCodePatterns(content, filePath),
  ];

  const blockable = findings.filter(f => shouldBlock(f.severity));

  if (blockable.length === 0) {
    fileLog({ level: 'ALLOWED', type: 'write', file: filePath, totalFindings: findings.length, session_id: data.session_id });

    appendEvent({
      action: findings.length > 0 ? 'warning' : 'allowed',
      hook: 'PreToolUse',
      tool: data.tool_name,
      target: filePath,
      findings: findings.length > 0 ? findings.slice(0, 5).map(f => ({ rule: f.rule, severity: f.severity, line: f.line })) : undefined,
    });

    return allow();
  }

  // Build denial reason
  const lines = [`🚫 Security scan blocked this write (${blockable.length} issue(s) in ${filePath}):`];
  lines.push('');

  for (const f of blockable.slice(0, 5)) {
    const emoji = f.severity === SEVERITY.CRITICAL ? '🔴' : '🟠';
    lines.push(`${emoji} [${f.severity.toUpperCase()}] ${f.rule}`);
    lines.push(`   ${f.description}`);
    lines.push(`   Line ${f.line}: ${f.snippet}`);
  }

  if (blockable.length > 5) {
    lines.push(`   ... and ${blockable.length - 5} more issue(s)`);
  }

  lines.push('');
  lines.push('Fix the issues above and try again.');

  fileLog({
    level: 'BLOCKED',
    type: 'write',
    file: filePath,
    criticals: blockable.filter(f => f.severity === SEVERITY.CRITICAL).length,
    highs: blockable.filter(f => f.severity === SEVERITY.HIGH).length,
    findings: blockable.map(f => ({ rule: f.rule, severity: f.severity, line: f.line })),
    session_id: data.session_id,
  });

  appendEvent({
    action: 'blocked',
    hook: 'PreToolUse',
    tool: data.tool_name,
    target: filePath,
    reason: `${blockable.length} security issue(s) detected`,
    severity: blockable[0].severity,
    findings: blockable.slice(0, 10).map(f => ({ rule: f.rule, severity: f.severity, line: f.line, description: f.description })),
  });

  deny(lines.join('\n'));
}

// ── Main ──
async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;

  try {
    const data = JSON.parse(input);
    const { tool_name } = data;

    if (tool_name === 'Bash') {
      return handleBash(data);
    }

    if (['Write', 'Edit'].includes(tool_name)) {
      return handleWriteEdit(data);
    }

    // Unknown tool, allow through
    allow();

  } catch (e) {
    fileLog({ level: 'ERROR', error: e.message });
    // On error, always allow — never let a broken hook block Claude
    allow();
  }
}

if (require.main === module) {
  main();
} else {
  module.exports = { shouldBlock, handleBash, handleWriteEdit, SAFETY_LEVEL, LEVELS };
}
