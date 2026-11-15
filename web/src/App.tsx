import { useCallback, useEffect, useState } from "react";
import {
  ChevronsUpDown,
  FolderKanban,
  LogOut,
  Moon,
  ShieldCheck,
  Sun,
} from "lucide-react";
import { meta } from "./api/meta.gen";
import { userMeta } from "./api/user-meta.gen";
import {
  ApiError,
  authConfig,
  authMe,
  getToken,
  setToken,
  type AuthMe,
  userWorkspaces,
  workspaces,
} from "./api/client";
import { Dashboard } from "./components/Dashboard";
import { ResourceView } from "./components/ResourceView";
import { Alert, AlertDescription } from "./components/ui/alert";
import { Avatar, AvatarFallback, AvatarImage } from "./components/ui/avatar";
import { Button } from "./components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./components/ui/dropdown-menu";
import { Input } from "./components/ui/input";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarSeparator,
  SidebarTrigger,
} from "./components/ui/sidebar";
import { TooltipProvider } from "./components/ui/tooltip";

type WorkspaceOption = { id: string; name: string };
type RouteState = { admin: boolean; view: string; ws: string };

function readRoute(): RouteState {
  const path = decodeURIComponent(location.pathname).replace(/^\/+|\/+$/g, "");
  if (!path) return { admin: false, view: "overview", ws: "" };
  const parts = path.split("/");
  if (parts[0] === "admin") return { admin: true, view: parts[1] || "overview", ws: parts[2] || "" };
  if (parts[0] === "workspaces") {
    if (!parts[1]) return { admin: false, view: "workspaces", ws: "" };
    return { admin: false, view: parts[2] || "members", ws: parts[1] };
  }
  // There is intentionally no hash or legacy path compatibility. Unknown
  // history routes land on the user home page.
  return { admin: false, view: "overview", ws: "" };
}

function routePath(view: string, ws: string, admin: boolean) {
  if (admin) return view === "overview" ? `/admin${ws ? `/overview/${encodeURIComponent(ws)}` : ""}` : `/admin/${encodeURIComponent(view)}${ws ? `/${encodeURIComponent(ws)}` : ""}`;
  if (view === "workspaces") return "/workspaces";
  if (view === "overview" || !ws) return "/";
  return `/workspaces/${encodeURIComponent(ws)}/${encodeURIComponent(view)}`;
}

export function App() {
  const initialToken = getToken();
  const initialRoute = readRoute();
  const [token, setTok] = useState(initialToken);
  const [authenticated, setAuthenticated] = useState(() => Boolean(initialToken));
  const [authError, setAuthError] = useState("");
  const [identity, setIdentity] = useState<AuthMe | null>(null);
  const [adminMode, setAdminMode] = useState(() => initialRoute.admin || Boolean(initialToken));
  const [dark, setDark] = useState(() => localStorage.getItem("agentd.theme") === "dark");
  const [wsList, setWsList] = useState<WorkspaceOption[]>([]);
  const [{ admin, view, ws }, setRoute] = useState<RouteState>(initialRoute);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem("agentd.theme", dark ? "dark" : "light");
  }, [dark]);

  useEffect(() => {
    const update = () => setRoute(readRoute());
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);

  useEffect(() => {
    void authMe().then((me) => {
      setIdentity(me);
      if (me) {
        // An OIDC browser session is the active principal. Do not let a
        // bootstrap token left in localStorage override its workspace mode.
        setToken("");
        setTok("");
        setAuthenticated(true);
        if (me.instance_admin && initialRoute.admin) setAdminMode(true);
        else if (!initialRoute.admin) setAdminMode(false);
      }
    }).catch(() => undefined);
    void authConfig().catch(() => undefined);
  }, []);

  const go = useCallback((nextView: string, nextWs = ws, mode = adminMode) => {
    const nextPath = routePath(nextView, nextWs, mode);
    if (location.pathname !== nextPath) history.pushState({}, "", nextPath);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, [adminMode, ws]);

  useEffect(() => {
    const instanceAdmin = Boolean(token) || Boolean(identity?.instance_admin);
    if (admin || !token || !instanceAdmin) return;
    const nextView = view === "workspaces" ? "workspaces" : view === "overview" ? "overview" : view;
    const nextWs = nextView === "workspaces" || nextView === "overview" ? "" : ws;
    setAdminMode(true);
    localStorage.setItem("agentd.adminMode", "true");
    go(nextView, nextWs, true);
  }, [admin, go, identity?.instance_admin, token, view, ws]);

  const loadWs = useCallback(async () => {
    try {
      const list = adminMode ? await workspaces() : await userWorkspaces();
      const items = list.map((w) => ({ id: w.id || w.name, name: w.name }));
      setWsList(items);
      setAuthError("");
      if (adminMode && view === "overview" && ws) {
        go("overview", "", true);
        return;
      }
      const current = items.find((item) => item.id === ws || item.name === ws);
      if (current && current.id !== ws) go(view, current.id);
      else if (!ws && !adminMode && view === "overview") go("workspaces", "", false);
      else if (!ws && items.length && view !== "overview" && view !== "workspaces") go(view, items[0].id);
      else if (ws && !current && view !== "overview") go("overview", "");
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setAuthError("Your session has expired.");
        setAuthenticated(false);
        setTok("");
      }
    }
  }, [adminMode, go, view, ws]);

  useEffect(() => {
    if (authenticated) void loadWs();
  }, [authenticated, loadWs]);

  const logout = () => {
    void fetch("/auth/logout", { credentials: "same-origin" });
    setToken("");
    setTok("");
    setAuthenticated(false);
    setIdentity(null);
    setAdminMode(false);
    localStorage.removeItem("agentd.adminMode");
    go("overview", "", false);
  };

  if (!authenticated) {
    return <Login error={authError} onLogin={(value) => { setToken(value); setTok(value); setAuthenticated(true); setAdminMode(true); }} />;
  }

  const surfaceMeta = adminMode ? meta : userMeta;
  const global = adminMode ? surfaceMeta.resources.filter((r) => r.scope === "global") : [];
  const scoped = surfaceMeta.resources.filter((r) => r.scope === "workspace");
  const current = surfaceMeta.resources.find((r) => r.key === view);
  const readOnly = !adminMode && ["nodes", "services"].includes(view);
  const workspaceView = view !== "overview" && surfaceMeta.resources.some((r) => r.key === view && r.scope === "workspace");
  const selectedWorkspace = wsList.find((item) => item.id === ws || item.name === ws);
  const workspaceLabel = selectedWorkspace?.name || ws || "Select workspace";

  const selectWorkspace = (nextWs: string) => {
    go(workspaceView ? view : (adminMode ? "workspaces" : "members"), nextWs);
  };

  const setMode = (nextAdmin: boolean) => {
    if (!nextAdmin) {
      setToken("");
      setTok("");
    }
    setAdminMode(nextAdmin);
    localStorage.setItem("agentd.adminMode", String(nextAdmin));
    const nextView = view === "overview" ? (nextAdmin ? "overview" : "workspaces") : view;
    const nextWs = nextView === "overview" || nextView === "workspaces" ? "" : ws;
    go(nextView, nextWs, nextAdmin);
  };

  const navItem = (key: string, label: string, workspace = "") => (
    <SidebarMenuItem key={key}>
      <SidebarMenuButton asChild isActive={view === key} tooltip={label}>
        <a href={routePath(key, workspace, adminMode)} onClick={(event) => { event.preventDefault(); go(key, workspace); }}>
          <span>{label}</span>
        </a>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );

  return (
    <TooltipProvider>
    <SidebarProvider>
      <Sidebar collapsible="icon" variant="sidebar">
        <SidebarHeader>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton size="lg" asChild>
                <a href={routePath("overview", "", adminMode)} onClick={(event) => { event.preventDefault(); go("overview", "", adminMode); }}>
                  <span className="flex size-8 items-center justify-center rounded-lg bg-sidebar-primary text-xs font-semibold text-sidebar-primary-foreground">a</span>
                  <span className="flex flex-col text-left text-sm leading-tight"><span className="font-semibold">agentserver</span><span className="text-xs text-sidebar-foreground/70">{adminMode ? "Instance admin" : "Workspace"}</span></span>
                </a>
              </SidebarMenuButton>
            </SidebarMenuItem>
            <SidebarMenuItem>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground">
                    <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-sidebar-accent text-sidebar-accent-foreground">
                      <FolderKanban className="size-4" />
                    </span>
                    <span className="grid flex-1 text-left text-sm leading-tight">
                      <span className="truncate font-semibold">{workspaceLabel}</span>
                      <span className="truncate text-xs text-sidebar-foreground/70">{wsList.length ? "Workspace" : "No workspaces"}</span>
                    </span>
                    <ChevronsUpDown className="ml-auto size-4" />
                  </SidebarMenuButton>
                </DropdownMenuTrigger>
                <DropdownMenuContent side="bottom" align="start" className="w-[--radix-dropdown-menu-trigger-width] min-w-56 rounded-lg">
                  {wsList.length ? wsList.map((workspace) => (
                    <DropdownMenuItem key={workspace.id} onSelect={() => selectWorkspace(workspace.id)}>
                      <FolderKanban />
                      <span className="truncate">{workspace.name}</span>
                    </DropdownMenuItem>
                  )) : <DropdownMenuItem disabled>No workspaces</DropdownMenuItem>}
                </DropdownMenuContent>
              </DropdownMenu>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>

        <SidebarContent>
          {adminMode && (
            <SidebarGroup>
              <SidebarGroupLabel>Administration</SidebarGroupLabel>
              <SidebarGroupContent><SidebarMenu>{navItem("overview", "Overview")}{global.map((resource) => navItem(resource.key, resource.label))}</SidebarMenu></SidebarGroupContent>
            </SidebarGroup>
          )}
          <SidebarGroup>
            <SidebarGroupLabel>{adminMode ? "Workspaces" : "Workspace"}</SidebarGroupLabel>
            <SidebarGroupContent><SidebarMenu>
              {!adminMode && surfaceMeta.resources.some((resource) => resource.key === "workspaces") && navItem("workspaces", "Workspaces")}
              {scoped.map((resource) => navItem(resource.key, resource.label, ws))}
            </SidebarMenu></SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>

        <SidebarSeparator />
        <SidebarFooter>
          <SidebarMenu>
            <SidebarMenuItem>
              <UserMenu identity={identity} adminMode={adminMode} canSwitchMode={Boolean(identity?.instance_admin)} dark={dark} onDark={setDark} onMode={() => setMode(!adminMode)} onLogout={logout} />
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>

      <SidebarInset>
        <header className="flex h-12 shrink-0 items-center gap-2 border-b px-4 md:hidden"><SidebarTrigger /></header>
        <main className="min-w-0 flex-1 p-4 md:p-8">
          {current ? <ResourceView key={`${current.key}:${ws}:${adminMode}`} r={current} ws={ws} surface={adminMode ? "admin" : "user"} readOnly={readOnly} onChanged={current.key === "workspaces" ? loadWs : undefined} /> : adminMode ? <Dashboard /> : <UserHome identity={identity} />}
        </main>
      </SidebarInset>
    </SidebarProvider>
    </TooltipProvider>
  );
}

function UserHome({ identity }: { identity: AuthMe | null }) {
  return (
    <div className="mx-auto flex w-full max-w-3xl flex-col gap-6">
      <header><h1 className="text-2xl font-semibold tracking-tight">Workspace</h1><p className="text-sm text-muted-foreground">{identity?.name || identity?.email || "Signed in"}. Choose a workspace above.</p></header>
      <Card><CardHeader><CardTitle>No workspace selected</CardTitle><CardDescription>Select a workspace from the sidebar to view its resources.</CardDescription></CardHeader><CardContent><p className="text-sm text-muted-foreground">Your access is limited to the workspaces where you have membership.</p></CardContent></Card>
    </div>
  );
}

function UserMenu({ identity, adminMode, canSwitchMode, dark, onDark, onMode, onLogout }: { identity: AuthMe | null; adminMode: boolean; canSwitchMode: boolean; dark: boolean; onDark: (value: boolean) => void; onMode: () => void; onLogout: () => void }) {
  const label = identity?.name || identity?.email || (canSwitchMode ? "Instance admin" : "User");
  const initials = label.slice(0, 1).toUpperCase();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground">
          <Avatar size="sm" className="rounded-lg"><AvatarImage src={identity?.picture} alt="" /><AvatarFallback className="rounded-lg">{initials}</AvatarFallback></Avatar>
          <span className="grid flex-1 text-left text-sm leading-tight"><span className="truncate font-semibold">{label}</span>{identity?.email && <span className="truncate text-xs text-sidebar-foreground/70">{identity.email}</span>}</span>
          <ChevronsUpDown className="ml-auto size-4" />
        </SidebarMenuButton>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="min-w-56 rounded-lg" side="top" align="start" sideOffset={4}>
        <DropdownMenuLabel className="p-0 font-normal"><div className="flex items-center gap-2 px-1 py-1.5 text-left text-sm"><Avatar size="sm" className="rounded-lg"><AvatarImage src={identity?.picture} alt="" /><AvatarFallback className="rounded-lg">{initials}</AvatarFallback></Avatar><div className="grid flex-1 text-left text-sm leading-tight"><span className="truncate font-semibold">{label}</span>{identity?.email && <span className="truncate text-xs text-muted-foreground">{identity.email}</span>}</div></div></DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => onDark(!dark)}>{dark ? <Sun /> : <Moon />}{dark ? "Light mode" : "Dark mode"}</DropdownMenuItem>
        {canSwitchMode && <DropdownMenuItem onSelect={onMode}><ShieldCheck />{adminMode ? "Workspace mode" : "Admin mode"}</DropdownMenuItem>}
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={onLogout}><LogOut />Log out</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function Login({ onLogin, error }: { onLogin: (token: string) => void; error: string }) {
  const [value, setValue] = useState("");
  const [oidc, setOidc] = useState(false);
  useEffect(() => { void fetch("/auth/config", { credentials: "same-origin" }).then((response) => response.json()).then((config) => setOidc(Boolean(config.oidc_enabled))).catch(() => undefined); }, []);
  return (
    <div className="flex min-h-svh items-center justify-center bg-muted/30 p-4">
      <Card className="w-full max-w-sm">
        <CardHeader><CardTitle>Sign in to agentserver</CardTitle><CardDescription>{oidc ? "Use the configured organization identity provider." : "Use the instance admin token to continue."}</CardDescription></CardHeader>
        <CardContent>
          {oidc ? <Button asChild className="w-full"><a href="/auth/login">Sign in with OIDC</a></Button> : <form className="grid gap-4" onSubmit={(event) => { event.preventDefault(); if (value.trim()) onLogin(value.trim()); }}><Input type="password" autoFocus value={value} onChange={(event) => setValue(event.target.value)} placeholder="Admin token" aria-label="Admin token" />{error && <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>}<Button type="submit" className="w-full">Sign in</Button><Button asChild variant="link" className="w-full"><a href="/auth/login">Sign in with OIDC</a></Button></form>}
        </CardContent>
      </Card>
    </div>
  );
}
