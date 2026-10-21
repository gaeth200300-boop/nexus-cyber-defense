import {
  Activity,
  Boxes,
  BrainCircuit,
  Bug,
  Command,
  FileText,
  Fingerprint,
  FlaskConical,
  Gauge,
  GitBranch,
  Globe2,
  GraduationCap,
  History,
  LayoutDashboard,
  Lock,
  Radar,
  ScanLine,
  ServerCog,
  ShieldCheck,
  Siren,
  Swords,
  Target,
  Users,
  UserRound,
  Waypoints,
  type LucideIcon
} from "lucide-react";

export interface NavItem {
  to: string;
  labelKey: string;
  icon: LucideIcon;
  adminOnly?: boolean;
  end?: boolean;
}

export interface NavGroup {
  labelKey: string;
  items: NavItem[];
}

export const navGroups: NavGroup[] = [
  {
    labelKey: "nav.command",
    items: [
      { to: "/dashboard", labelKey: "nav.dashboard", icon: LayoutDashboard },
      { to: "/academy", labelKey: "nav.academy", icon: GraduationCap }
    ]
  },
  {
    labelKey: "nav.security",
    items: [
      { to: "/web", labelKey: "nav.web", icon: Globe2 },
      { to: "/network", labelKey: "nav.network", icon: Radar },
      { to: "/scans", labelKey: "nav.scans", icon: ScanLine },
      { to: "/findings", labelKey: "nav.findings", icon: Bug },
      { to: "/assets", labelKey: "nav.assets", icon: Boxes }
    ]
  },
  {
    labelKey: "nav.intelligence",
    items: [
      { to: "/intel", labelKey: "nav.intel", icon: Fingerprint },
      { to: "/asm", labelKey: "nav.asm", icon: Activity },
      { to: "/soc", labelKey: "nav.soc", icon: Siren },
      { to: "/copilot", labelKey: "nav.copilot", icon: BrainCircuit }
    ]
  },
  {
    labelKey: "nav.commandPlatform",
    items: [
      { to: "/graph", labelKey: "nav.graph", icon: GitBranch },
      { to: "/timeline", labelKey: "nav.timeline", icon: History },
      { to: "/posture", labelKey: "nav.posture", icon: Gauge },
      { to: "/rule-studio", labelKey: "nav.ruleStudio", icon: Target },
      { to: "/workbench", labelKey: "nav.workbench", icon: Swords },
      { to: "/evidence", labelKey: "nav.evidence", icon: Lock },
      { to: "/purple", labelKey: "nav.purple", icon: Waypoints },
      { to: "/knowledge", labelKey: "nav.knowledge", icon: GitBranch }
    ]
  },
  {
    labelKey: "nav.operations",
    items: [
      { to: "/labs", labelKey: "nav.labs", icon: FlaskConical },
      { to: "/reports", labelKey: "nav.reports", icon: FileText }
    ]
  },
  {
    labelKey: "nav.workspace",
    items: [
      { to: "/projects", labelKey: "nav.projects", icon: ShieldCheck },
      { to: "/profile", labelKey: "nav.profile", icon: UserRound },
      { to: "/admin", labelKey: "nav.platform", icon: ServerCog, adminOnly: true }
    ]
  }
];

export const adminNavItems: NavItem[] = [
  { to: "/admin?tab=users", labelKey: "admin.users", icon: Users },
  { to: "/admin?tab=audit", labelKey: "admin.audit", icon: FileText },
  { to: "/admin?tab=jobs", labelKey: "admin.jobs", icon: Gauge },
  { to: "/admin?tab=settings", labelKey: "admin.settings", icon: Command }
];

export const allNavItems = navGroups.flatMap((group) => group.items);
