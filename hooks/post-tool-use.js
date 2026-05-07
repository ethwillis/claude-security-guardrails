#!/usr/bin/env node
/**
 * Claude Code PostToolUse Hook - Security scanner reporter
 *
 * Runs AFTER Write/Edit tool calls execute.
 * Scans the modified file, saves results to dashboard, logs activity.
 * PostToolUse hooks cannot block — they only observe and report.
 *
 * Setup in .claude/settings.json:
 * {
 *   "hooks": {
 *     "PostToolUse": [{
 *       "matcher": "Write|Edit",
 *       "hooks": [{ "type": "command", "command": "node /path/to/post-tool-use.js" }]
 *     }]
 *   }
 * }
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { appendEvent } = require('../scanner/utils/activityLog');

const LOG_DIR = path.join(process.env.HOME || process.env.USERPROFILE || os.homedir(), '.claude', 'hooks-logs');

function fileLog(data) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    const file = path.join(LOG_DIR, `${new Date().toISOString().slice(0, 10)}.jsonl`);
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), hook: 'security-scanner-post', ...data }) + '\n');
  } catch {}
}

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;

  try {
    const data = JSON.parse(input);
    const { tool_name, tool_input, session_id, cwd } = data;

    if (!['Write', 'Edit'].includes(tool_name)) {
      return console.log('{}');
    }

    const filePath = tool_input?.file_path;
    if (!filePath) {
      return console.log('{}');
    }

    const resolvedPath = path.isAbsolute(filePath)
      ? filePath
      : path.resolve(cwd || process.cwd(), filePath);

    const scannerPath = path.join(__dirname, '..', 'scanner', 'index.js');
    const { scan } = require(scannerPath);

    const result = await scan(resolvedPath, { dryRun: false });

    if (result.totalFindings > 0) {
      fileLog({
        level: 'FINDINGS',
        file: filePath,
        score: result.score,
        total: result.totalFindings,
        severityCounts: result.severityCounts,
        session_id,
      });

      appendEvent({
        action: 'findings',
        hook: 'PostToolUse',
        tool: tool_name,
        target: filePath,
        score: result.score,
        totalFindings: result.totalFindings,
        severityCounts: result.severityCounts,
        findings: result.findings.slice(0, 10).map(f => ({
          rule: f.rule,
          severity: f.severity,
          line: f.line,
          description: f.description,
        })),
      });
    } else {
      fileLog({ level: 'CLEAN', file: filePath, session_id });

      appendEvent({
        action: 'allowed',
        hook: 'PostToolUse',
        tool: tool_name,
        target: filePath,
        score: 100,
      });
    }

  } catch (e) {
    fileLog({ level: 'ERROR', error: e.message });
  }

  console.log('{}');
}

if (require.main === module) {
  main();
} else {
  module.exports = { fileLog };
}
