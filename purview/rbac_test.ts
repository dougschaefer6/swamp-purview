import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import {
  ediscoveryAuthSupport,
  explainEdiscoveryFailure,
  isAppOnly,
  PurviewPwshError,
} from "./_pwsh.ts";
import { model } from "./rbac.ts";
import { model as auditModel } from "./audit.ts";

const BEGIN = "<<<SWAMP_JSON_BEGIN>>>";
const END = "<<<SWAMP_JSON_END>>>";
const CONNECTED = "<<<SWAMP_PV_CONNECTED>>>";

const APP_ONLY = {
  organization: "contoso.onmicrosoft.com",
  appId: "test-app",
  certificateThumbprint: "test-thumb",
};
const DELEGATED = {
  organization: "contoso.onmicrosoft.com",
  userPrincipalName: "admin@example.com",
};

/**
 * Put fake `pwsh` and `az` executables first on PATH. pwsh prints whatever is
 * in $FAKE_PWSH_OUT to stdout and $FAKE_PWSH_ERR to stderr, exits with
 * $FAKE_PWSH_CODE, and copies the generated script to $FAKE_PWSH_SCRIPT so a
 * test can assert on it; az returns a canned Graph token. No real PowerShell
 * session or tenant is ever touched.
 */
async function withFakeShell(
  pwshStdout: string,
  fn: (scriptPath: string) => Promise<void>,
  opts: { stderr?: string; exitCode?: number } = {},
): Promise<void> {
  const dir = await Deno.makeTempDir({ prefix: "purview-test-" });
  const outPath = `${dir}/out.txt`;
  const errPath = `${dir}/err.txt`;
  const scriptPath = `${dir}/script.ps1`;
  await Deno.writeTextFile(outPath, pwshStdout);
  await Deno.writeTextFile(errPath, opts.stderr ?? "");
  await Deno.writeTextFile(
    `${dir}/pwsh`,
    `#!/bin/sh\nfor a in "$@"; do last="$a"; done\ncp "$last" "$FAKE_PWSH_SCRIPT"\ncat "$FAKE_PWSH_OUT"\ncat "$FAKE_PWSH_ERR" >&2\nexit ${
      opts.exitCode ?? 0
    }\n`,
  );
  await Deno.writeTextFile(
    `${dir}/az`,
    `#!/bin/sh\necho '{"accessToken":"test-tok"}'\n`,
  );
  await Deno.chmod(`${dir}/pwsh`, 0o755);
  await Deno.chmod(`${dir}/az`, 0o755);

  const oldPath = Deno.env.get("PATH") ?? "";
  Deno.env.set("PATH", `${dir}:${oldPath}`);
  Deno.env.set("FAKE_PWSH_OUT", outPath);
  Deno.env.set("FAKE_PWSH_ERR", errPath);
  Deno.env.set("FAKE_PWSH_SCRIPT", scriptPath);
  try {
    await fn(scriptPath);
  } finally {
    Deno.env.set("PATH", oldPath);
    Deno.env.delete("FAKE_PWSH_OUT");
    Deno.env.delete("FAKE_PWSH_ERR");
    Deno.env.delete("FAKE_PWSH_SCRIPT");
    await Deno.remove(dir, { recursive: true });
  }
}

/** Stdout of a run that connected and emitted `value` between the markers. */
function payload(value: unknown): string {
  return `WARNING: module banner\n${CONNECTED}\n${BEGIN}\n${
    JSON.stringify(value)
  }\n${END}\n`;
}

/**
 * `notices` collects the info-level lines that flag a problem (app-only
 * best-effort, failed lookups). They are logged at info because swamp hides
 * warn-level output without -v; the context deliberately has no `warn`, so
 * any code path that still calls it throws here.
 */
function makeContext(globalArgs: Record<string, unknown>) {
  const notices: string[] = [];
  const written: Array<{ spec: string; name: string; data: unknown }> = [];
  const flags = /unsupported|could not be read|lookup failed/;
  return {
    warnings: notices,
    written,
    context: {
      globalArgs,
      logger: {
        info: (m: string, p?: Record<string, unknown>) => {
          if (flags.test(m)) notices.push(`${m} ${JSON.stringify(p ?? {})}`);
        },
      },
      writeResource: (spec: string, name: string, data: unknown) => {
        written.push({ spec, name, data });
        return Promise.resolve({ spec, name });
      },
    },
  };
}

// deno-lint-ignore no-explicit-any
type AnyExecute = (args: any, context: any) => Promise<unknown>;
const listCaseAdmins = model.methods.listCaseAdmins.execute as AnyExecute;
const auditPrincipals = model.methods.auditPrincipals.execute as AnyExecute;
const listCases = model.methods.listCases.execute as AnyExecute;
const syncRoleGroups = model.methods.syncRoleGroups.execute as AnyExecute;

/** Stub Graph so resolvePrincipal returns one fixed example user. */
async function withGraphUser(
  user: { displayName: string; userPrincipalName: string },
  fn: () => Promise<void>,
): Promise<void> {
  const realFetch = globalThis.fetch;
  globalThis.fetch = () =>
    Promise.resolve(
      new Response(
        JSON.stringify({ id: "00000000-0000-0000-0000-000000000003", ...user }),
        { status: 200 },
      ),
    );
  try {
    await fn();
  } finally {
    globalThis.fetch = realFetch;
  }
}

Deno.test("auth mode: app-only needs both appId and thumbprint", () => {
  assert(isAppOnly(APP_ONLY));
  assert(!isAppOnly(DELEGATED));
  assert(
    !isAppOnly({ organization: "contoso.onmicrosoft.com", appId: "test-app" }),
  );
  assertEquals(ediscoveryAuthSupport(APP_ONLY), "best-effort");
  assertEquals(ediscoveryAuthSupport(DELEGATED), "supported");
});

Deno.test("explainEdiscoveryFailure only rewrites app-only post-connect failures", () => {
  const afterConnect = new PurviewPwshError("remote 403", true, 1);
  assertEquals(
    explainEdiscoveryFailure(
      DELEGATED,
      "Get-eDiscoveryCaseAdmin",
      afterConnect,
    ),
    afterConnect,
  );
  const explained = explainEdiscoveryFailure(
    APP_ONLY,
    "Get-eDiscoveryCaseAdmin",
    afterConnect,
  );
  assertStringIncludes(explained.message, "unsupported");
  assertStringIncludes(explained.message, "userPrincipalName");
  assertStringIncludes(explained.message, "New-ServicePrincipal");
  assertStringIncludes(explained.message, "eDiscoveryManager");
  assertStringIncludes(explained.message, "-EnableSearchOnlySession");
  assertStringIncludes(explained.message, "3.10.1");
  assertStringIncludes(explained.message, "remote 403");
  assertEquals(explained.cause, afterConnect);

  // Failures before or outside a connected session keep their own message:
  // pwsh missing, Import-Module, certificate not found, Connect 401.
  const beforeConnect = new PurviewPwshError("Connect 401", false, 1);
  assertEquals(
    explainEdiscoveryFailure(APP_ONLY, "Get-ComplianceCase", beforeConnect),
    beforeConnect,
  );
  const pwshMissing = new Deno.errors.NotFound("pwsh not found");
  assertEquals(
    explainEdiscoveryFailure(APP_ONLY, "Get-ComplianceCase", pwshMissing),
    pwshMissing,
  );
});

Deno.test("listCaseAdmins delegated: supported, no warning", async () => {
  await withFakeShell(payload([{ Name: "Alice Example" }]), async () => {
    const { context, warnings, written } = makeContext(DELEGATED);
    await listCaseAdmins({}, context);
    assertEquals(warnings.length, 0);
    assertEquals(written.length, 1);
    assertEquals(written[0].data, {
      name: "Alice Example",
      authSupport: "supported",
    });
  });
});

Deno.test("listCaseAdmins app-only: warns and tags best-effort", async () => {
  await withFakeShell(payload([{ Name: "Alice Example" }]), async () => {
    const { context, warnings, written } = makeContext(APP_ONLY);
    await listCaseAdmins({}, context);
    assertEquals(warnings.length, 1);
    assertStringIncludes(warnings[0], "unsupported");
    assertEquals(
      (written[0].data as { authSupport: string }).authSupport,
      "best-effort",
    );
  });
});

Deno.test("listCaseAdmins app-only failure after connect explains the cause", async () => {
  // Connected, then no JSON markers: the remote cmdlet threw.
  await withFakeShell(
    `${CONNECTED}\nGet-eDiscoveryCaseAdmin: access denied\n`,
    async () => {
      const { context } = makeContext(APP_ONLY);
      const err = await assertRejects(() => listCaseAdmins({}, context));
      assertStringIncludes((err as Error).message, "app-only (certificate)");
      assertStringIncludes((err as Error).message, "no JSON payload");
    },
  );
});

Deno.test("listCaseAdmins app-only failure before connect is not rewritten", async () => {
  await withFakeShell(
    "",
    async () => {
      const { context } = makeContext(APP_ONLY);
      const err = await assertRejects(() => listCaseAdmins({}, context));
      assert(!(err as Error).message.includes("app-only (certificate)"));
      assertStringIncludes((err as Error).message, "before connect completed");
      assertStringIncludes((err as Error).message, "certificate not found");
    },
    {
      stderr:
        "Connect-ExchangeOnline: certificate not found in the user store\n",
      exitCode: 1,
    },
  );
});

Deno.test("B1: empty payload plus a stderr error record rejects", async () => {
  await withFakeShell(
    payload([]),
    async (scriptPath) => {
      const { context, written } = makeContext(DELEGATED);
      const err = await assertRejects(() => listCaseAdmins({}, context));
      assertStringIncludes((err as Error).message, "error records on stderr");
      assertStringIncludes((err as Error).message, "remote server error");
      assertEquals(written.length, 0);
      const script = await Deno.readTextFile(scriptPath);
      assertStringIncludes(script, "Get-eDiscoveryCaseAdmin -ErrorAction Stop");
    },
    { stderr: "Get-eDiscoveryCaseAdmin: remote server error\n" },
  );
});

Deno.test("B1: empty payload with a non-zero exit rejects", async () => {
  await withFakeShell(
    payload([]),
    async () => {
      const { context, written } = makeContext(APP_ONLY);
      const err = await assertRejects(() => listCaseAdmins({}, context));
      assertStringIncludes((err as Error).message, "exit 1");
      // Connected, so the app-only hint applies.
      assertStringIncludes((err as Error).message, "app-only (certificate)");
      assertEquals(written.length, 0);
    },
    { exitCode: 1 },
  );
});

Deno.test("B1: listCases uses -ErrorAction Stop and rejects on stderr errors", async () => {
  await withFakeShell(
    payload([]),
    async (scriptPath) => {
      const { context } = makeContext(DELEGATED);
      await assertRejects(() => listCases({}, context));
      const script = await Deno.readTextFile(scriptPath);
      assertStringIncludes(script, "Get-ComplianceCase -ErrorAction Stop");
    },
    { stderr: "Get-ComplianceCase: remote server error\n" },
  );
});

Deno.test("stderr WARNING lines alone do not fail a run", async () => {
  await withFakeShell(
    payload([{ Name: "Alice Example" }]),
    async () => {
      const { context, written } = makeContext(DELEGATED);
      await listCaseAdmins({}, context);
      assertEquals(written.length, 1);
    },
    { stderr: "WARNING: a newer module version is available\n" },
  );
});

Deno.test("listCaseAdmins delegated failure passes through unchanged", async () => {
  await withFakeShell("boom\n", async () => {
    const { context } = makeContext(DELEGATED);
    const err = await assertRejects(() => listCaseAdmins({}, context));
    assert(!(err as Error).message.includes("app-only"));
  });
});

Deno.test("auditPrincipals: failed case-admin lookup yields null, not false", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = () =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          id: "00000000-0000-0000-0000-000000000001",
          displayName: "Alice Example",
          userPrincipalName: "alice@example.com",
        }),
        { status: 200 },
      ),
    );
  try {
    await withFakeShell(
      payload([{
        groups: [{
          name: "eDiscoveryManager",
          roles: ["Compliance Search", "Export"],
          members: ["Alice Example"],
        }],
        caseAdmins: [],
        caseAdminError: "The term 'Get-eDiscoveryCaseAdmin' is not recognized",
      }]),
      async (scriptPath) => {
        const { context, warnings, written } = makeContext(APP_ONLY);
        await auditPrincipals({ principals: ["alice@example.com"] }, context);
        const rec = written[0].data as Record<string, unknown>;
        assertEquals(rec.isCaseAdmin, null);
        assertEquals(rec.canExport, true);
        assertEquals(rec.caseAdminAuthSupport, "best-effort");
        assert(warnings.some((w) => w.includes("rather than false")));
        assert(warnings.some((w) => w.includes("unsupported")));
        // The script must surface, not swallow, the case-admin error.
        const script = await Deno.readTextFile(scriptPath);
        assertStringIncludes(script, "$adminError = [string]$_");
        // Role-group reads are untouched by the auth-mode handling.
        assertStringIncludes(script, "Get-RoleGroupMember");
      },
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});

Deno.test("auditPrincipals delegated: case admin resolved as boolean", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = () =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          id: "00000000-0000-0000-0000-000000000002",
          displayName: "Bob Example",
          userPrincipalName: "bob@example.com",
        }),
        { status: 200 },
      ),
    );
  try {
    await withFakeShell(
      payload([{
        groups: [],
        caseAdmins: ["Bob Example (Shared)"],
        caseAdminError: null,
      }]),
      async () => {
        const { context, warnings, written } = makeContext(DELEGATED);
        await auditPrincipals({ principals: ["bob@example.com"] }, context);
        const rec = written[0].data as Record<string, unknown>;
        assertEquals(rec.isCaseAdmin, true);
        assertEquals(rec.caseAdminAuthSupport, "supported");
        assertEquals(warnings.length, 0);
      },
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});

Deno.test("syncRoleGroups app-only: no eDiscovery notice", async () => {
  await withFakeShell(
    payload([{ name: "eDiscoveryManager", roles: ["Export"], members: [] }]),
    async () => {
      const { context, warnings, written } = makeContext(APP_ONLY);
      await syncRoleGroups({}, context);
      assertEquals(warnings.length, 0);
      assertEquals(written.length, 1);
    },
  );
});

Deno.test("A6 syncRoleGroups: unreadable membership is null with the error", async () => {
  await withFakeShell(
    payload([
      {
        name: "eDiscoveryManager",
        roles: ["Export"],
        members: [],
        membersError: "Get-RoleGroupMember: remote timeout",
      },
      {
        name: "Reviewer",
        roles: ["Review"],
        members: ["Bob Example"],
        membersError: null,
      },
    ]),
    async (scriptPath) => {
      const { context, warnings, written } = makeContext(DELEGATED);
      await syncRoleGroups({}, context);
      const byName = Object.fromEntries(
        written.map((w) => [w.name, w.data as Record<string, unknown>]),
      );
      assertEquals(byName.eDiscoveryManager.members, null);
      assertStringIncludes(
        String(byName.eDiscoveryManager.membersError),
        "remote timeout",
      );
      assertEquals(byName.Reviewer.members, ["Bob Example"]);
      assertEquals(byName.Reviewer.membersError, null);
      assert(warnings.some((w) => w.includes("could not be read")));
      const script = await Deno.readTextFile(scriptPath);
      assertStringIncludes(script, "catch { $mErr = [string]$_ }");
    },
  );
});

Deno.test("A6 auditPrincipals: unreadable egress group makes canExport null", async () => {
  await withGraphUser(
    { displayName: "Alice Example", userPrincipalName: "alice@example.com" },
    () =>
      withFakeShell(
        payload([{
          groups: [
            {
              name: "OrganizationManagement",
              roles: ["Case Management", "Compliance Search"],
              members: ["Alice Example"],
              membersError: null,
            },
            {
              name: "eDiscoveryManager",
              roles: ["Compliance Search", "Export"],
              members: [],
              membersError: "Get-RoleGroupMember: remote timeout",
            },
          ],
          caseAdmins: [],
          caseAdminError: null,
        }]),
        async () => {
          const { context, warnings, written } = makeContext(DELEGATED);
          await auditPrincipals({ principals: ["alice@example.com"] }, context);
          const rec = written[0].data as Record<string, unknown>;
          // Search is known from a readable group; export is unknown.
          assertEquals(rec.canSearch, true);
          assertEquals(rec.canExport, null);
          assertEquals(rec.membershipErrors, [{
            roleGroup: "eDiscoveryManager",
            error: "Get-RoleGroupMember: remote timeout",
          }]);
          assertEquals(rec.isCaseAdmin, false);
          assert(warnings.some((w) => w.includes("could not be read")));
        },
      ),
  );
});

Deno.test("A6 auditPrincipals: a readable grant stays true despite other errors", async () => {
  await withGraphUser(
    { displayName: "Bob Example", userPrincipalName: "bob@example.com" },
    () =>
      withFakeShell(
        payload([{
          groups: [
            {
              name: "eDiscoveryManager",
              roles: ["Compliance Search", "Export"],
              members: ["Bob Example"],
              membersError: null,
            },
            {
              name: "Reviewer",
              roles: ["Review"],
              members: [],
              membersError: "Get-RoleGroupMember: remote timeout",
            },
          ],
          caseAdmins: [],
          caseAdminError: null,
        }]),
        async () => {
          const { context, written } = makeContext(DELEGATED);
          await auditPrincipals({ principals: ["bob@example.com"] }, context);
          const rec = written[0].data as Record<string, unknown>;
          assertEquals(rec.canSearch, true);
          assertEquals(rec.canExport, true);
        },
      ),
  );
});

Deno.test("models carry 2026.10.07.1 with an identity upgrade", () => {
  for (const m of [model, auditModel]) {
    assertEquals(m.version, "2026.10.07.1");
    const last = m.upgrades[m.upgrades.length - 1];
    assertEquals(last.toVersion, "2026.10.07.1");
    const old = { organization: "contoso.onmicrosoft.com" };
    assertEquals(last.upgradeAttributes(old), old);
  }
});
