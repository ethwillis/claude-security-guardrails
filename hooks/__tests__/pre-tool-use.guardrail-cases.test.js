const { spawnSync } = require('child_process');
const path = require('path');

const HOOK = path.join(__dirname, '..', 'pre-tool-use.js');

function runHook(payload, envOverrides) {
  const env = { ...process.env, ...(envOverrides || {}) };
  const res = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify(payload),
    encoding: 'utf8',
    env,
  });
  if (res.status !== 0) {
    throw new Error(`hook exited ${res.status}: ${res.stderr}`);
  }
  return JSON.parse(res.stdout.trim());
}

function expectDeny(out, patternIdSubstr) {
  const decision = out?.hookSpecificOutput?.permissionDecision;
  const reason = out?.hookSpecificOutput?.permissionDecisionReason || '';
  if (decision !== 'deny') {
    throw new Error(`expected deny, got ${JSON.stringify(out)}`);
  }
  if (patternIdSubstr && !reason.includes(patternIdSubstr)) {
    throw new Error(`expected reason to contain "${patternIdSubstr}", got: ${reason}`);
  }
}

const cases = [
  {
    name: 'Write bad.js with AWS access key',
    payload: {
      tool_name: 'Write',
      tool_input: {
        file_path: 'bad.js',
        content: "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';\n",
      },
      session_id: 'test',
    },
    expect: 'AWS',
  },
  {
    name: 'Bash: cat .env',
    payload: {
      tool_name: 'Bash',
      tool_input: { command: 'cat .env' },
      session_id: 'test',
    },
    expect: 'cat-env',
  },
  {
    name: 'Bash: git push --force origin main',
    payload: {
      tool_name: 'Bash',
      tool_input: { command: 'git push --force origin main' },
      session_id: 'test',
    },
    expect: 'git-force',
  },
  {
    name: 'Bash: Remove-Item -Recurse -Force C:\\Windows\\Temp',
    payload: {
      tool_name: 'Bash',
      tool_input: { command: 'Remove-Item -Recurse -Force C:\\Windows\\Temp' },
      session_id: 'test',
    },
    expect: 'ps-remove',
  },
];

let failed = 0;
for (const c of cases) {
  try {
    const out = runHook(c.payload);
    expectDeny(out, c.expect);
    console.log(`  PASS  ${c.name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL  ${c.name}`);
    console.log(`        ${e.message}`);
  }
}

// Regression: on Windows, HOME is unset. The hook must still deny dangerous
// actions (previously it crashed building LOG_DIR and fell open via the
// outer catch in main()).
try {
  const out = runHook(
    { tool_name: 'Bash', tool_input: { command: 'cat .env' }, session_id: 'test' },
    { HOME: '' }
  );
  expectDeny(out, 'cat-env');
  console.log(`  PASS  Windows regression: HOME unset, cat .env still blocked`);
} catch (e) {
  failed++;
  console.log(`  FAIL  Windows regression: HOME unset, cat .env still blocked`);
  console.log(`        ${e.message}`);
}

const total = cases.length + 1;
if (failed > 0) {
  console.log(`\n${failed} of ${total} cases failed`);
  process.exit(1);
}
console.log(`\nAll ${total} guardrail cases blocked as expected.`);
