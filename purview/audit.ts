import { z } from "npm:zod@4.3.6";
import {
  emitJson,
  PurviewGlobalArgsSchema,
  PurviewMethodContext,
  pwshJson,
  sanitizeInstanceName,
  warnIfAppOnlyEdiscovery,
} from "./_pwsh.ts";

const AffectedItemSchema = z
  .object({
    subject: z.string().nullish(),
    internetMessageId: z.string().nullish(),
    parentFolder: z.string().nullish(),
  })
  .passthrough();

const DeletionEventSchema = z
  .object({
    time: z.string(),
    actor: z.string(),
    operation: z.string(),
    folder: z.string().nullish(),
    client: z.string().nullish(),
    clientIp: z.string().nullish(),
    items: z.array(AffectedItemSchema),
  })
  .passthrough();

const DeletionProfileSchema = z
  .object({
    principal: z.string(),
    windowStart: z.string(),
    windowEnd: z.string(),
    eventCount: z.number(),
    itemCount: z.number(),
    byOperation: z.record(z.string(), z.number()),
    byFolder: z.record(z.string(), z.number()),
    events: z.array(DeletionEventSchema),
  })
  .passthrough();

const ChatThreadSchema = z
  .object({
    threadId: z.string(),
    communicationType: z.string().nullish(),
    chatName: z.string().nullish(),
    actors: z.array(z.string()),
    sharedBySweptPrincipals: z.boolean(),
    firstSeen: z.string(),
    lastSeen: z.string(),
    eventCount: z.number(),
    byOperation: z.record(z.string(), z.number()),
    ambiguousUpdateCount: z.number(),
  })
  .passthrough();

const PreviewItemSchema = z
  .object({
    subject: z.string().nullish(),
    sender: z.string().nullish(),
    recipients: z.string().nullish(),
    receivedTime: z.string().nullish(),
    folder: z.string().nullish(),
    location: z.string().nullish(),
    fromRecoverableItems: z.boolean(),
  })
  .passthrough();

const PreviewResultSchema = z
  .object({
    searchName: z.string(),
    status: z.string().nullish(),
    itemCount: z.number(),
    recoverableItemCount: z.number(),
    items: z.array(PreviewItemSchema),
  })
  .passthrough();

/** Mailbox audit operations that destroy or displace a message. */
const DELETION_OPERATIONS = [
  "SoftDelete",
  "HardDelete",
  "MoveToDeletedItems",
] as const;

/**
 * Recoverable Items subfolders. An item surfacing from one of these was deleted
 * by the user and survives only because a hold or single-item recovery caught
 * it, so its presence is itself the evidence.
 */
const RECOVERABLE_FOLDERS = [
  "Deletions",
  "Purges",
  "SubstrateHolds",
  "DiscoveryHolds",
  "Versions",
];

interface RawRecord {
  t: string;
  actor: string;
  op: string;
  rt: string;
  data: string;
}

/**
 * `@dougschaefer/purview-audit` — unified audit log forensics for questions of
 * the form "did this person delete that message, and can we prove it".
 *
 * Separate from `@dougschaefer/purview-rbac` because it answers a different
 * question against a different endpoint. RBAC reads role groups over the
 * compliance session; this reads Search-UnifiedAuditLog, which exists only in a
 * real Exchange Online session — connecting with the compliance ConnectionUri
 * yields a session where the cmdlet is simply not a recognised command, which
 * is a confusing failure rather than an obvious one.
 *
 * Two constraints shape the whole design, and both are silent failures if
 * ignored:
 *
 * Search-UnifiedAuditLog rejects a long date range outright with "Search
 * duration too long" rather than truncating, and it caps a single response
 * regardless of ResultSize. So sweepActivity walks the window in chunks and
 * pages each chunk with ReturnLargeSet until the page comes back empty,
 * de-duplicating on Identity because ReturnLargeSet returns unsorted results
 * that repeat across pages. A caller who issues one wide query instead gets
 * zero rows and a warning on stderr, which reads exactly like "this person
 * deleted nothing".
 *
 * Teams logs a message edit and a message deletion under the same MessageUpdated
 * operation, so chat deletion cannot be established from audit metadata alone.
 * This model reports those as ambiguousUpdateCount and refuses to characterise
 * them as deletions; resolving one requires item-level content review via
 * previewSearch against a compliance search that includes Recoverable Items.
 */
export const model = {
  type: "@dougschaefer/purview-audit",
  version: "2026.10.07.1",
  globalArguments: PurviewGlobalArgsSchema,
  upgrades: [
    {
      toVersion: "2026.10.07.1",
      description:
        "previewSearch warns that app-only auth is best-effort for eDiscovery cmdlets; globalArguments unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    deletionProfile: {
      description:
        "Every mailbox deletion one principal performed in a window, with the subject and message id of each affected item",
      schema: DeletionProfileSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    chatThread: {
      description:
        "A Teams conversation the swept principals participated in, with its per-operation event counts",
      schema: ChatThreadSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
    previewResult: {
      description:
        "Item-level metadata for a completed compliance search, flagging which items came from Recoverable Items",
      schema: PreviewResultSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    sweepActivity: {
      description:
        "Sweep the unified audit log for a set of principals over a date range and produce, per principal, every mailbox deletion with the subject and message id of each affected item, plus the Teams threads they participated in. Fan-out by design: one session walks the whole window in chunks rather than one call per principal per slice. Chat message deletions are reported as ambiguous rather than asserted, because Teams logs edits and deletes identically.",
      arguments: z.object({
        principals: z
          .array(z.string())
          .min(1)
          .describe(
            "Mailbox UPNs to sweep. Verify spelling first — an address that does not resolve returns zero rows, which is indistinguishable from a principal who deleted nothing.",
          ),
        startDate: z
          .string()
          .describe(
            "Window start, ISO date. Audit retention is finite and shorter than most investigations assume; a start date beyond retention silently returns nothing for the uncovered portion.",
          ),
        endDate: z.string().describe("Window end, ISO date"),
        chunkDays: z
          .number()
          .int()
          .min(1)
          .max(90)
          .default(15)
          .describe(
            "Days per search slice. Raising this risks the 'Search duration too long' rejection, which surfaces as a warning and zero rows rather than an error.",
          ),
        recordTypes: z
          .array(z.string())
          .default(["ExchangeItem", "ExchangeItemGroup", "MicrosoftTeams"])
          .describe("Audit record types to sweep"),
      }),
      execute: async (
        args: {
          principals: string[];
          startDate: string;
          endDate: string;
          chunkDays: number;
          recordTypes: string[];
        },
        context: PurviewMethodContext,
      ) => {
        const raw = (await pwshJson(
          context.globalArgs,
          emitJson(
            `$start = [datetime]::Parse($P.startDate)
  $end   = [datetime]::Parse($P.endDate)
  $chunk = [int]$P.chunkDays
  $rows  = New-Object System.Collections.ArrayList
  $cursor = $start
  while ($cursor -lt $end) {
    $slice = $cursor.AddDays($chunk)
    if ($slice -gt $end) { $slice = $end }
    foreach ($rt in @($P.recordTypes)) {
      # A fresh SessionId per slice per record type: ReturnLargeSet pages are
      # scoped to the session, and reusing one across slices silently drops
      # results from the later slice.
      $sid = [guid]::NewGuid().ToString()
      do {
        $batch = Search-UnifiedAuditLog -StartDate $cursor -EndDate $slice \`
          -UserIds @($P.principals) -RecordType $rt -SessionId $sid \`
          -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction SilentlyContinue
        # @() is load-bearing: a page holding exactly one record arrives as a
        # scalar, and AddRange rejects it.
        if ($batch) { [void]$rows.AddRange(@($batch)) }
      } while ($batch -and $batch.Count -gt 0)
    }
    $cursor = $slice
  }
  $rows | Sort-Object Identity -Unique | ForEach-Object {
    [PSCustomObject]@{
      t     = $_.CreationDate.ToString('o')
      actor = [string]$_.UserIds
      op    = [string]$_.Operations
      rt    = [string]$_.RecordType
      data  = [string]$_.AuditData
    }
  }`,
          ),
          {
            principals: args.principals,
            startDate: args.startDate,
            endDate: args.endDate,
            chunkDays: args.chunkDays,
            recordTypes: args.recordTypes,
          },
          "exchange",
        )) as RawRecord[] | null;

        const records = raw ?? [];
        const swept = new Set(
          args.principals.map((p) => p.toLowerCase()),
        );

        // --- mailbox deletions, per principal -----------------------------
        const profiles = new Map<
          string,
          z.infer<typeof DeletionProfileSchema>
        >();
        for (const p of args.principals) {
          profiles.set(p.toLowerCase(), {
            principal: p,
            windowStart: args.startDate,
            windowEnd: args.endDate,
            eventCount: 0,
            itemCount: 0,
            byOperation: {},
            byFolder: {},
            events: [],
          });
        }

        // --- Teams threads -------------------------------------------------
        const threads = new Map<string, z.infer<typeof ChatThreadSchema>>();

        for (const rec of records) {
          let data: Record<string, unknown>;
          try {
            data = JSON.parse(rec.data) as Record<string, unknown>;
          } catch {
            continue;
          }
          const actor = (rec.actor ?? "").toLowerCase();

          if ((DELETION_OPERATIONS as readonly string[]).includes(rec.op)) {
            const profile = profiles.get(actor);
            if (profile) {
              const affected = (data.AffectedItems ?? []) as Array<
                Record<string, unknown>
              >;
              const items = affected.map((it) => ({
                subject: (it.Subject as string) ?? null,
                internetMessageId: (it.InternetMessageId as string) ?? null,
                parentFolder: ((it.ParentFolder as Record<string, unknown>)
                  ?.Path as string) ??
                  null,
              }));
              profile.events.push({
                time: rec.t,
                actor: rec.actor,
                operation: rec.op,
                folder:
                  ((data.Folder as Record<string, unknown>)?.Path as string) ??
                    null,
                client: (data.ClientInfoString as string) ?? null,
                clientIp: (data.ClientIP as string) ?? null,
                items,
              });
              profile.eventCount += 1;
              profile.itemCount += items.length;
              profile.byOperation[rec.op] = (profile.byOperation[rec.op] ?? 0) +
                1;
              for (const it of items) {
                const f = it.parentFolder ?? "(unknown)";
                profile.byFolder[f] = (profile.byFolder[f] ?? 0) + 1;
              }
            }
          }

          const threadId = data.ChatThreadId as string | undefined;
          if (threadId) {
            let t = threads.get(threadId);
            if (!t) {
              t = {
                threadId,
                communicationType: (data.CommunicationType as string) ?? null,
                chatName: (data.ChatName as string) ?? null,
                actors: [],
                sharedBySweptPrincipals: false,
                firstSeen: rec.t,
                lastSeen: rec.t,
                eventCount: 0,
                byOperation: {},
                ambiguousUpdateCount: 0,
              };
              threads.set(threadId, t);
            }
            if (!t.actors.includes(rec.actor)) t.actors.push(rec.actor);
            if (!t.chatName && data.ChatName) {
              t.chatName = data.ChatName as string;
            }
            if (rec.t < t.firstSeen) t.firstSeen = rec.t;
            if (rec.t > t.lastSeen) t.lastSeen = rec.t;
            t.eventCount += 1;
            t.byOperation[rec.op] = (t.byOperation[rec.op] ?? 0) + 1;
            // MessageUpdated covers both an edit and a delete. Counted, never
            // characterised — see the model note.
            if (rec.op === "MessageUpdated") t.ambiguousUpdateCount += 1;
          }
        }

        for (const t of threads.values()) {
          t.sharedBySweptPrincipals = t.actors.filter((a) =>
            swept.has(a.toLowerCase())
          ).length > 1;
        }

        const handles = [];
        for (const profile of profiles.values()) {
          handles.push(
            await context.writeResource(
              "deletionProfile",
              sanitizeInstanceName(profile.principal),
              profile,
            ),
          );
        }
        for (const t of threads.values()) {
          handles.push(
            await context.writeResource(
              "chatThread",
              sanitizeInstanceName(t.threadId),
              t,
            ),
          );
        }

        const shared = [...threads.values()].filter((t) =>
          t.sharedBySweptPrincipals
        );
        context.logger.info(
          "Swept {records} audit records: {deletions} deletion events across {principals} principals, {threads} Teams threads ({shared} shared, {ambiguous} ambiguous chat updates)",
          {
            records: records.length,
            deletions: [...profiles.values()].reduce(
              (n, p) => n + p.eventCount,
              0,
            ),
            principals: profiles.size,
            threads: threads.size,
            shared: shared.length,
            ambiguous: shared.reduce((n, t) => n + t.ambiguousUpdateCount, 0),
          },
        );
        return { dataHandles: handles };
      },
    },

    previewSearch: {
      description:
        "Run a Preview action against an already-completed compliance search and return item-level metadata — sender, recipients, subject, date and source folder — flagging which items came from Recoverable Items and are therefore deleted content that a hold caught. This is the eDiscovery Standard path to item detail; review sets require Premium, and the export route needs the Windows-only ClickOnce export tool. Caps at the service limit of roughly 1000 items, so scope the underlying search narrowly.",
      arguments: z.object({
        searchName: z
          .string()
          .describe("Name of a completed compliance search to preview"),
        timeoutMinutes: z
          .number()
          .int()
          .min(1)
          .max(60)
          .default(20)
          .describe("How long to poll for the preview action to complete"),
      }),
      execute: async (
        args: { searchName: string; timeoutMinutes: number },
        context: PurviewMethodContext,
      ) => {
        warnIfAppOnlyEdiscovery(
          context.globalArgs,
          context.logger,
          "New-ComplianceSearchAction -Preview",
        );
        const raw = await pwshJson(
          context.globalArgs,
          emitJson(
            `$name = $P.searchName + '_Preview'
  $existing = $null
  try { $existing = Get-ComplianceSearchAction -Identity $name -ErrorAction Stop } catch {}
  if (-not $existing) {
    New-ComplianceSearchAction -SearchName $P.searchName -Preview -ErrorAction Stop | Out-Null
  }
  $deadline = (Get-Date).AddMinutes([int]$P.timeoutMinutes)
  do {
    Start-Sleep -Seconds 15
    $a = Get-ComplianceSearchAction -Identity $name -Details -ErrorAction SilentlyContinue
  } while ($a -and $a.Status -ne 'Completed' -and (Get-Date) -lt $deadline)
  [PSCustomObject]@{
    Status  = [string]$a.Status
    Results = [string]$a.Results
  }`,
          ),
          { searchName: args.searchName, timeoutMinutes: args.timeoutMinutes },
          // Ordinary compliance session, NOT searchOnly. A search-only session
          // is scoped to running searches; New-ComplianceSearchAction -Preview
          // in one comes back as a bare remote 403, which reads like a missing
          // Preview role and sends you auditing RBAC that is already correct.
          "compliance",
        );

        const r = (Array.isArray(raw) ? raw[0] : raw) as {
          Status?: string;
          Results?: string;
        } | null;

        // Results is a semicolon-delimited key:value blob, one record per line,
        // not JSON — parsed defensively because the field set varies by item.
        const items: z.infer<typeof PreviewItemSchema>[] = [];
        for (const line of (r?.Results ?? "").split(/\r?\n/)) {
          if (!line.includes("Location:")) continue;
          const fields: Record<string, string> = {};
          for (const part of line.split(";")) {
            const idx = part.indexOf(":");
            if (idx === -1) continue;
            fields[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
          }
          const folder = fields["Folder"] ?? fields["Original path"] ?? "";
          items.push({
            subject: fields["Subject"] ?? null,
            sender: fields["Sender"] ?? fields["From"] ?? null,
            recipients: fields["Recipients"] ?? fields["To"] ?? null,
            receivedTime: fields["Received Time"] ?? fields["Sent Time"] ??
              null,
            folder: folder || null,
            location: fields["Location"] ?? null,
            fromRecoverableItems: RECOVERABLE_FOLDERS.some((f) =>
              folder.includes(f)
            ),
          });
        }

        const recoverable = items.filter((i) => i.fromRecoverableItems).length;
        const record = {
          searchName: args.searchName,
          status: r?.Status ?? null,
          itemCount: items.length,
          recoverableItemCount: recoverable,
          items,
        };

        context.logger.info(
          "Preview of {name}: status={status} items={items}, {recoverable} from Recoverable Items (deleted content preserved by hold)",
          {
            name: args.searchName,
            status: record.status,
            items: record.itemCount,
            recoverable,
          },
        );
        return {
          dataHandles: [
            await context.writeResource(
              "previewResult",
              sanitizeInstanceName(args.searchName),
              record,
            ),
          ],
        };
      },
    },
  },
};
