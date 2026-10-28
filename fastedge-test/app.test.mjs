import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { defineTestSuite, runAndExit, runFlow, mockOrigins, assertFinalStatus } from '@gcoredev/fastedge-test/test';

const here = dirname(fileURLToPath(import.meta.url));
const ORIGIN = 'https://origin.example.com';

// Each scenario's env vars live in fastedge-test/env/<scenario>/.env (FASTEDGE_VAR_ENV_*).
async function flow(runner, scenario, cookies) {
  await runner.applyDotenv(true, resolve(here, 'env', scenario));
  const mocks = mockOrigins();
  try {
    mocks.origin(ORIGIN).intercept({ path: '/' })
      .reply(200, 'ok', { headers: { 'content-type': 'text/plain', 'set-cookie': cookies } });
    return await runFlow(runner, { url: `${ORIGIN}/` });
  } finally {
    await mocks.close();
  }
}

// Set-Cookie values as an array, ignoring empty entries.
// KNOWN GAP (2026-10-28): the filter clears Set-Cookie with set(None) before
// re-adding each cookie; fastedge-test 0.2.6 turns that removal into an extra
// empty `Set-Cookie: ""`. Whether core-proxy (where response hooks run) does the
// same is unverified on the edge — see context/new-org FUTURE F-10. Empties are
// filtered here so the suite tests the cookie logic, not the runner's removal.
function setCookies(result) {
  const v = result.finalResponse.headers['set-cookie'];
  return (Array.isArray(v) ? v : v ? [v] : []).filter((c) => c.trim() !== '');
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const has = (cookie, attr) => cookie.split(';').map((s) => s.trim()).includes(attr);

await runAndExit(defineTestSuite({
  wasmPath: resolve(here, '../target/wasm32-wasip1/release/harden_cookies.wasm'),
  tests: [
    {
      name: 'hardens every cookie with all attributes, keeping each Set-Cookie',
      async run(runner) {
        const result = await flow(runner, 'all', ['a=1; Path=/', 'b=2; SameSite=Lax']);
        assertFinalStatus(result, 200);
        const cookies = setCookies(result);
        assert(cookies.length === 2, `expected 2 Set-Cookie headers, got ${JSON.stringify(cookies)}`);
        for (const c of cookies) {
          assert(has(c, 'Secure') && has(c, 'HttpOnly') && has(c, 'SameSite=Strict'), `not hardened: ${c}`);
        }
        assert(!cookies.some((c) => /SameSite=Lax/i.test(c)), 'SameSite=Lax must be replaced');
      },
    },
    {
      name: 'only hardens the cookie named in COOKIE_NAME',
      async run(runner) {
        const cookies = setCookies(await flow(runner, 'targeted', ['a=1', 'b=2']));
        const a = cookies.find((c) => c.startsWith('a='));
        const b = cookies.find((c) => c.startsWith('b='));
        assert(a === 'a=1', `cookie a must be untouched, got ${a}`);
        assert(b && has(b, 'Secure') && !has(b, 'HttpOnly'), `cookie b must get Secure only, got ${b}`);
      },
    },
    {
      name: 'does not duplicate an attribute that is already present',
      async run(runner) {
        const [c] = setCookies(await flow(runner, 'all', ['a=1; Secure; HttpOnly']));
        const count = (attr) => c.split(';').filter((s) => s.trim() === attr).length;
        assert(count('Secure') === 1 && count('HttpOnly') === 1, `duplicated attributes: ${c}`);
      },
    },
    {
      name: 'leaves cookies unchanged when no attribute is enabled',
      async run(runner) {
        assert(JSON.stringify(setCookies(await flow(runner, 'none-enabled', ['a=1']))) === '["a=1"]', 'cookie must be unchanged');
      },
    },
    {
      name: 'leaves cookies unchanged when COOKIE_NAME is unset',
      async run(runner) {
        assert(JSON.stringify(setCookies(await flow(runner, 'unset', ['a=1']))) === '["a=1"]', 'cookie must be unchanged');
      },
    },
  ],
}));
