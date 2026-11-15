import { useEffect, useState } from "react";
import { CheckCircle2, Copy, Server, TriangleAlert } from "lucide-react";
import { serverInfo, status, ApiError } from "../api/client";
import { copy } from "./format";
import { Alert, AlertDescription, AlertTitle } from "./ui/alert";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./ui/card";
import { Button } from "./ui/button";

type Info = Awaited<ReturnType<typeof serverInfo>>;
type Stat = Awaited<ReturnType<typeof status>>;

export function Dashboard() {
  const [info, setInfo] = useState<Info | null>(null);
  const [stat, setStat] = useState<Stat | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let live = true;
    const tick = async () => {
      try {
        const [server, current] = await Promise.all([serverInfo(), status()]);
        if (live) {
          setInfo(server);
          setStat(current);
          setError("");
        }
      } catch (e) {
        if (live) setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
      }
    };
    void tick();
    const timer = window.setInterval(tick, 10_000);
    return () => {
      live = false;
      window.clearInterval(timer);
    };
  }, []);

  const uptime = stat?.uptime_seconds ?? 0;
  const cards = [
    ["Workspaces", stat?.workspaces],
    ["Nodes online", stat ? `${stat.nodes_online ?? 0} / ${stat.nodes_total ?? 0}` : undefined],
    ["Relays connected", stat ? `${stat.relays_connected ?? 0} / ${stat.relays_registered ?? 0}` : undefined],
    ["Certificates pending", stat?.certs_pending],
    ["Uptime", stat ? `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m` : undefined],
  ] as const;

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-6">
      <header className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
        <p className="text-sm text-muted-foreground">
          {info ? `agentserver ${info.version}${info.domain ? ` · ${info.domain}` : ""}` : "Loading server information…"}
        </p>
      </header>

      {error && (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>Unable to load the overview</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        {cards.map(([label, value]) => (
          <Card key={label}>
            <CardHeader className="pb-2">
              <CardDescription>{label}</CardDescription>
              <CardTitle className="text-2xl tabular-nums">{value ?? "—"}</CardTitle>
            </CardHeader>
          </Card>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {info && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Server className="size-4" /> Server identity</CardTitle>
              <CardDescription>
                Relays pin this key. Nodes pin their workspace key instead.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-start gap-2 rounded-lg border bg-muted/30 p-3">
                <code className="min-w-0 flex-1 break-all text-xs">{info.public_key}</code>
                <Button variant="ghost" size="icon-sm" onClick={() => copy(info.public_key)} aria-label="Copy server public key">
                  <Copy />
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle>Getting started</CardTitle>
            <CardDescription>Set up the control plane in a few steps.</CardDescription>
          </CardHeader>
          <CardContent>
            <ol className="grid gap-3 text-sm text-muted-foreground">
              <li className="flex gap-3"><CheckCircle2 className="mt-0.5 size-4 shrink-0 text-primary" /><span>Register a relay or start agentrelay with a relay token.</span></li>
              <li className="flex gap-3"><CheckCircle2 className="mt-0.5 size-4 shrink-0 text-primary" /><span>Create a workspace; agentd selects a relay candidate automatically.</span></li>
              <li className="flex gap-3"><CheckCircle2 className="mt-0.5 size-4 shrink-0 text-primary" /><span>Create a join token and run <code className="rounded bg-muted px-1.5 py-0.5 text-xs">agentd join &lt;link&gt;</code> on each machine.</span></li>
              <li className="flex gap-3"><CheckCircle2 className="mt-0.5 size-4 shrink-0 text-primary" /><span>Add routes and policies; nodes pick them up immediately.</span></li>
            </ol>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
