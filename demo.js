// Prints the risk check for every sample request: `npm run demo`
const E = require('./riskEngine.js');

for (const s of E.SAMPLES) {
  const r = E.analyze(s.input);
  console.log(`\n${s.label}  [${r.level.toUpperCase()} risk, score ${r.score}/100]`);
  console.log(`  -> ${r.headline}`);
  if (!r.flags.length) console.log('  No warning signs.');
  for (const f of r.flags) console.log(`  ! ${f.title} (+${f.points}): ${f.detail}`);
  console.log(`  What to do: ${r.actions[0]}`);
}
