import * as DialogPrimitive from "@radix-ui/react-dialog";
import * as TabsPrimitive from "@radix-ui/react-tabs";
import * as SwitchPrimitive from "@radix-ui/react-switch";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import {
  forwardRef,
  useState,
  type ButtonHTMLAttributes,
  type HTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes
} from "react";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  Inbox,
  Loader2,
  X,
  type LucideIcon
} from "lucide-react";
import { cn, copyText, initials, severityClasses, severityDot, statusClasses, titleCase } from "../lib/utils";

/* ------------------------------------------------------------------ Buttons */

export type ButtonVariant = "primary" | "secondary" | "ghost" | "outline" | "danger" | "success";
export type ButtonSize = "sm" | "md" | "lg" | "icon";

const buttonVariants: Record<ButtonVariant, string> = {
  primary:
    "border-transparent bg-accent text-white shadow-[0_8px_30px_-12px_rgb(var(--accent)/.8)] hover:bg-accent/90 active:translate-y-px",
  secondary:
    "border-line bg-panel2 text-ink hover:border-accent/35 hover:bg-panel3 active:translate-y-px",
  ghost: "border-transparent bg-transparent text-muted hover:bg-panel2 hover:text-ink",
  outline: "border-line bg-transparent text-ink hover:border-accent/40 hover:bg-accent/5",
  danger: "border-rose-500/30 bg-rose-500/10 text-rose-300 hover:bg-rose-500/20",
  success: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20"
};

const buttonSizes: Record<ButtonSize, string> = {
  sm: "h-8 gap-1.5 rounded-lg px-3 text-xs",
  md: "h-10 gap-2 rounded-xl px-4 text-sm",
  lg: "h-11 gap-2 rounded-xl px-5 text-sm",
  icon: "h-9 w-9 rounded-xl"
};

export function buttonClass(variant: ButtonVariant = "primary", size: ButtonSize = "md", className?: string) {
  return cn(
    "inline-flex select-none items-center justify-center border font-medium transition-all duration-200 focus-ring disabled:pointer-events-none disabled:opacity-45",
    buttonVariants[variant],
    buttonSizes[size],
    className
  );
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  icon?: LucideIcon;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "primary", size = "md", loading, icon: Icon, children, disabled, ...props },
  ref
) {
  return (
    <button
      ref={ref}
      className={buttonClass(variant, size, className)}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : Icon ? <Icon className="h-4 w-4" /> : null}
      {children}
    </button>
  );
});

export const IconButton = forwardRef<HTMLButtonElement, ButtonProps>(function IconButton(
  { className, variant = "ghost", size = "icon", children, ...props },
  ref
) {
  return (
    <Button ref={ref} variant={variant} size={size} className={cn("shrink-0", className)} {...props}>
      {children}
    </Button>
  );
});

/* -------------------------------------------------------------------- Cards */

export function Card({ className, children, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("surface-card", className)} {...props}>
      {children}
    </div>
  );
}

export function SectionHeader({
  title,
  subtitle,
  actions,
  className,
  icon: Icon
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  className?: string;
  icon?: LucideIcon;
}) {
  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-3", className)}>
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          {Icon ? (
            <span className="grid h-7 w-7 place-items-center rounded-lg border border-accent/20 bg-accent/10 text-accent">
              <Icon className="h-3.5 w-3.5" />
            </span>
          ) : null}
          <h2 className="truncate text-sm font-semibold tracking-tight text-ink">{title}</h2>
        </div>
        {subtitle ? <p className="mt-1.5 max-w-2xl text-xs leading-relaxed text-muted">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  subtitle,
  actions,
  icon: Icon,
  children
}: {
  eyebrow?: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  icon?: LucideIcon;
  children?: ReactNode;
}) {
  return (
    <header className="animate-fade-in">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          {eyebrow ? (
            <div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.22em] text-accent2">
              {Icon ? <Icon className="h-3.5 w-3.5" /> : <span className="h-1 w-1 rounded-full bg-accent2" />}
              <span>{eyebrow}</span>
            </div>
          ) : null}
          <h1 className="font-display text-2xl font-semibold leading-tight tracking-[-0.02em] text-ink sm:text-3xl">
            {title}
          </h1>
          {subtitle ? <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted">{subtitle}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {children ? <div className="mt-5">{children}</div> : null}
    </header>
  );
}

/* ------------------------------------------------------------------- Badges */

export function Badge({
  children,
  className,
  tone = "default",
  dot
}: {
  children: ReactNode;
  className?: string;
  tone?: "default" | "accent" | "success" | "warning" | "danger" | "info";
  dot?: boolean;
}) {
  const tones = {
    default: "border-line bg-panel2 text-muted",
    accent: "border-accent/25 bg-accent/10 text-accent",
    success: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
    warning: "border-amber-400/20 bg-amber-400/10 text-amber-300",
    danger: "border-rose-400/20 bg-rose-400/10 text-rose-300",
    info: "border-sky-400/20 bg-sky-400/10 text-sky-300"
  };
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.04em]",
        tones[tone],
        className
      )}
    >
      {dot ? <span className="h-1.5 w-1.5 rounded-full bg-current" /> : null}
      {children}
    </span>
  );
}

export function SeverityBadge({
  severity,
  className,
  label
}: {
  severity?: string | null;
  className?: string;
  label?: string;
}) {
  const { t } = useTranslation();
  if (!severity) return null;
  const key = severity.toLowerCase();
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.04em]",
        severityClasses[key] || severityClasses.info,
        className
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", severityDot[key] || severityDot.info)} />
      {label || t(`severity.${key}`, titleCase(key))}
    </span>
  );
}

export function StatusBadge({
  status,
  label,
  className
}: {
  status?: string | null;
  label?: string;
  className?: string;
}) {
  const { t } = useTranslation();
  if (!status) return null;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.04em]",
        statusClasses[status] || statusClasses.inactive,
        className
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current opacity-80" />
      {label || t(`status.${status}`, titleCase(status))}
    </span>
  );
}

/* ------------------------------------------------------------------- Inputs */

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input(
  { className, ...props },
  ref
) {
  return <input ref={ref} className={cn("input-field", className)} {...props} />;
});

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(
  function Textarea({ className, ...props }, ref) {
    return <textarea ref={ref} className={cn("input-field min-h-24 resize-y py-2.5", className)} {...props} />;
  }
);

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select(
  { className, children, ...props },
  ref
) {
  return (
    <select ref={ref} className={cn("input-field appearance-none bg-panel2 pe-9", className)} {...props}>
      {children}
    </select>
  );
});

export function Field({
  label,
  hint,
  children,
  className,
  required
}: {
  label?: ReactNode;
  hint?: ReactNode;
  children: ReactNode;
  className?: string;
  required?: boolean;
}) {
  return (
    <label className={cn("block space-y-1.5", className)}>
      {label ? (
        <span className="flex items-center gap-1 text-xs font-medium text-ink/90">
          {label}
          {required ? <span className="text-danger">*</span> : null}
        </span>
      ) : null}
      {children}
      {hint ? <span className="block text-[11px] leading-relaxed text-muted">{hint}</span> : null}
    </label>
  );
}

export function Switch({
  checked,
  onCheckedChange,
  disabled,
  label
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
  label?: ReactNode;
}) {
  return (
    <label className={cn("flex items-center gap-2.5", disabled ? "opacity-50" : "cursor-pointer")}>
      <SwitchPrimitive.Root
        checked={checked}
        onCheckedChange={onCheckedChange}
        disabled={disabled}
        className="relative h-5 w-9 shrink-0 rounded-full border border-line bg-panel3 transition data-[state=checked]:border-accent/50 data-[state=checked]:bg-accent/70 focus-ring"
      >
        <SwitchPrimitive.Thumb className="block h-3.5 w-3.5 translate-x-0.5 rounded-full bg-white shadow transition-transform data-[state=checked]:translate-x-[18px]" />
      </SwitchPrimitive.Root>
      {label ? <span className="text-xs text-muted">{label}</span> : null}
    </label>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
  className,
  disabled
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: ReactNode;
  className?: string;
  disabled?: boolean;
}) {
  return (
    <label className={cn("flex cursor-pointer items-start gap-2.5", disabled && "cursor-not-allowed opacity-50", className)}>
      <span
        className={cn(
          "mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded border transition",
          checked ? "border-accent bg-accent text-white" : "border-line bg-panel2"
        )}
      >
        {checked ? <Check className="h-3 w-3" /> : null}
      </span>
      <input
        type="checkbox"
        className="sr-only"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
      {label ? <span className="text-xs leading-relaxed text-muted">{label}</span> : null}
    </label>
  );
}

/* ------------------------------------------------------------------ Dialogs */

const modalSizes = {
  sm: "max-w-md",
  md: "max-w-xl",
  lg: "max-w-3xl",
  xl: "max-w-5xl",
  full: "max-w-[min(1100px,94vw)]"
};

export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  size = "md",
  icon: Icon
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  size?: keyof typeof modalSizes;
  icon?: LucideIcon;
}) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm data-[state=open]:animate-fade-in" />
        <DialogPrimitive.Content
          className={cn(
            "fixed left-1/2 top-1/2 z-[101] flex max-h-[90vh] w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-2xl border border-line bg-panel shadow-panel outline-none data-[state=open]:animate-scale-in",
            modalSizes[size]
          )}
        >
          <div className="flex items-start gap-3 border-b border-line/70 px-5 py-4">
            {Icon ? (
              <span className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-accent/20 bg-accent/10 text-accent">
                <Icon className="h-4 w-4" />
              </span>
            ) : null}
            <div className="min-w-0 flex-1">
              <DialogPrimitive.Title className="text-base font-semibold text-ink">{title}</DialogPrimitive.Title>
              {description ? (
                <DialogPrimitive.Description asChild>
                  <p className="mt-1 text-xs leading-relaxed text-muted">{description}</p>
                </DialogPrimitive.Description>
              ) : (
                <DialogPrimitive.Description className="sr-only">{title}</DialogPrimitive.Description>
              )}
            </div>
            <DialogPrimitive.Close className="grid h-8 w-8 place-items-center rounded-lg text-muted transition hover:bg-panel2 hover:text-ink focus-ring">
              <X className="h-4 w-4" />
              <span className="sr-only">Close</span>
            </DialogPrimitive.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5">{children}</div>
          {footer ? <div className="flex flex-wrap justify-end gap-2 border-t border-line/70 bg-panel2/40 px-5 py-3">{footer}</div> : null}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  cancelLabel,
  onConfirm,
  loading,
  danger
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  confirmLabel: string;
  cancelLabel: string;
  onConfirm: () => void;
  loading?: boolean;
  danger?: boolean;
}) {
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      description={description}
      size="sm"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            {cancelLabel}
          </Button>
          <Button variant={danger ? "danger" : "primary"} loading={loading} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="flex items-center gap-3 text-sm text-muted">
        <AlertTriangle className={cn("h-8 w-8 shrink-0", danger ? "text-danger" : "text-warn")} />
        <p>{description || title}</p>
      </div>
    </Modal>
  );
}

/* -------------------------------------------------------------------- Tabs */

export const Tabs = TabsPrimitive.Root;
export const TabsContent = TabsPrimitive.Content;

export function TabsList({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <TabsPrimitive.List
      className={cn(
        "no-scrollbar flex gap-1 overflow-x-auto rounded-xl border border-line bg-panel2/60 p-1",
        className
      )}
    >
      {children}
    </TabsPrimitive.List>
  );
}

export function TabsTrigger({
  value,
  children,
  count,
  icon: Icon
}: {
  value: string;
  children: ReactNode;
  count?: number;
  icon?: LucideIcon;
}) {
  return (
    <TabsPrimitive.Trigger
      value={value}
      className="flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium text-muted transition focus-ring hover:text-ink data-[state=active]:bg-panel3 data-[state=active]:text-ink data-[state=active]:shadow-sm"
    >
      {Icon ? <Icon className="h-3.5 w-3.5" /> : null}
      {children}
      {typeof count === "number" ? (
        <span className="rounded-full bg-panel px-1.5 py-0.5 text-[10px] tabular-nums text-muted">{count}</span>
      ) : null}
    </TabsPrimitive.Trigger>
  );
}

/* ----------------------------------------------------------------- Tooltip */

export function TooltipProvider({ children }: { children: ReactNode }) {
  return <TooltipPrimitive.Provider delayDuration={250}>{children}</TooltipPrimitive.Provider>;
}

export function Tooltip({ content, children }: { content: ReactNode; children: ReactNode }) {
  return (
    <TooltipPrimitive.Root>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          sideOffset={6}
          className="z-[300] max-w-64 rounded-lg border border-line bg-panel3 px-2.5 py-1.5 text-[11px] leading-relaxed text-ink shadow-panel animate-fade-in"
        >
          {content}
          <TooltipPrimitive.Arrow className="fill-panel3" />
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}

/* --------------------------------------------------------------- Feedback */

export function Progress({
  value,
  className,
  tone = "accent",
  indeterminate
}: {
  value: number;
  className?: string;
  tone?: "accent" | "success" | "danger" | "warning";
  indeterminate?: boolean;
}) {
  const tones = {
    accent: "bg-gradient-to-r from-accent to-accent2",
    success: "bg-gradient-to-r from-emerald-500 to-teal-400",
    danger: "bg-gradient-to-r from-rose-500 to-orange-400",
    warning: "bg-gradient-to-r from-amber-500 to-yellow-400"
  };
  return (
    <div className={cn("h-1.5 w-full overflow-hidden rounded-full bg-panel3", className)}>
      <div
        className={cn(
          "h-full rounded-full transition-[width] duration-500 ease-out",
          tones[tone],
          indeterminate && "animate-pulse-soft"
        )}
        style={{ width: `${Math.max(0, Math.min(100, value))}%` }}
      />
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn("h-5 w-5 animate-spin text-accent", className)} aria-label="Loading" />;
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("skeleton", className)} />;
}

export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
  className
}: {
  icon?: LucideIcon;
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-12 text-center", className)}>
      <div className="relative mb-4 grid h-14 w-14 place-items-center rounded-2xl border border-line bg-panel2 text-muted">
        <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-accent/10 to-transparent" />
        <Icon className="relative h-6 w-6" />
      </div>
      <h3 className="text-sm font-semibold text-ink">{title}</h3>
      {description ? <p className="mt-1.5 max-w-md text-xs leading-relaxed text-muted">{description}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
  title,
  description
}: {
  error?: unknown;
  onRetry?: () => void;
  title: ReactNode;
  description?: ReactNode;
}) {
  return (
    <Card className="p-6">
      <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center">
        <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-rose-400/20 bg-rose-400/10 text-rose-300">
          <AlertTriangle className="h-5 w-5" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-ink">{title}</p>
          <p className="mt-1 break-words text-xs leading-relaxed text-muted">
            {description || (error instanceof Error ? error.message : "The request could not be completed.")}
          </p>
        </div>
        {onRetry ? (
          <Button variant="secondary" size="sm" onClick={onRetry}>
            Retry
          </Button>
        ) : null}
      </div>
    </Card>
  );
}

/* ------------------------------------------------------------------ Stats */

export function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = "accent",
  footer,
  onClick,
  className
}: {
  label: ReactNode;
  value: ReactNode;
  sub?: ReactNode;
  icon?: LucideIcon;
  tone?: "accent" | "cyan" | "success" | "warning" | "danger" | "muted";
  footer?: ReactNode;
  onClick?: () => void;
  className?: string;
}) {
  const toneMap = {
    accent: "border-accent/15 bg-accent/[0.07] text-accent",
    cyan: "border-accent2/15 bg-accent2/[0.07] text-accent2",
    success: "border-emerald-400/15 bg-emerald-400/[0.07] text-emerald-300",
    warning: "border-amber-400/15 bg-amber-400/[0.07] text-amber-300",
    danger: "border-rose-400/15 bg-rose-400/[0.07] text-rose-300",
    muted: "border-line bg-panel2 text-muted"
  };
  const Wrapper = onClick ? "button" : "div";
  return (
    <Wrapper
      type={onClick ? "button" : undefined}
      onClick={onClick}
      className={cn(
        "surface-card group relative overflow-hidden p-4 text-start transition duration-300",
        onClick && "hover:-translate-y-0.5 hover:border-accent/25",
        className
      )}
    >
      <div className="pointer-events-none absolute -right-8 -top-10 h-24 w-24 rounded-full bg-accent/[0.035] blur-2xl transition group-hover:bg-accent/[0.09]" />
      <div className="relative flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted">{label}</p>
          <p className="mt-2 font-display text-2xl font-semibold leading-none tracking-tight text-ink tabular-nums">
            {value}
          </p>
          {sub ? <p className="mt-2 line-clamp-1 text-[11px] text-faint">{sub}</p> : null}
        </div>
        {Icon ? (
          <span className={cn("grid h-9 w-9 shrink-0 place-items-center rounded-xl border", toneMap[tone])}>
            <Icon className="h-4 w-4" />
          </span>
        ) : null}
      </div>
      {footer ? <div className="relative mt-3 border-t border-line/60 pt-2.5">{footer}</div> : null}
    </Wrapper>
  );
}

/* ------------------------------------------------------------------ Tables */

export interface TableColumn<T> {
  key: string;
  header: ReactNode;
  render: (row: T) => ReactNode;
  className?: string;
  headerClassName?: string;
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading,
  empty,
  onRowClick,
  className,
  rowClassName,
  skeletonRows = 5
}: {
  columns: TableColumn<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  loading?: boolean;
  empty?: ReactNode;
  onRowClick?: (row: T) => void;
  className?: string;
  rowClassName?: (row: T) => string;
  skeletonRows?: number;
}) {
  return (
    <div className={cn("overflow-x-auto", className)}>
      <table className="w-full min-w-[640px] border-collapse text-start">
        <thead>
          <tr className="border-b border-line/70">
            {columns.map((column) => (
              <th
                key={column.key}
                className={cn(
                  "whitespace-nowrap px-4 py-3 text-start text-[10px] font-semibold uppercase tracking-[0.1em] text-faint",
                  column.headerClassName
                )}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading
            ? Array.from({ length: skeletonRows }).map((_, rowIndex) => (
                <tr key={`skeleton-${rowIndex}`} className="border-b border-line/40">
                  {columns.map((column) => (
                    <td key={column.key} className={cn("px-4 py-3.5", column.className)}>
                      <Skeleton className="h-4 w-3/4" />
                    </td>
                  ))}
                </tr>
              ))
            : rows.map((row) => (
                <tr
                  key={rowKey(row)}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  className={cn(
                    "border-b border-line/40 transition last:border-0",
                    onRowClick && "cursor-pointer hover:bg-panel2/60",
                    rowClassName?.(row)
                  )}
                >
                  {columns.map((column) => (
                    <td key={column.key} className={cn("px-4 py-3 align-middle text-xs text-muted", column.className)}>
                      {column.render(row)}
                    </td>
                  ))}
                </tr>
              ))}
          {!loading && rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="p-0">
                {empty || <EmptyState title="No data" />}
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}

export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
  labels
}: {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
  labels: { previous: string; next: string; page: string; of: string };
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(total, page * pageSize);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line/60 px-4 py-3">
      <p className="text-[11px] tabular-nums text-faint">
        {start}–{end} / {total}
      </p>
      <div className="flex items-center gap-2">
        <Button
          size="sm"
          variant="ghost"
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
          aria-label={labels.previous}
        >
          <ChevronLeft className="h-4 w-4 rtl:hidden" />
          <ChevronRight className="hidden h-4 w-4 rtl:block" />
          <span className="hidden sm:inline">{labels.previous}</span>
        </Button>
        <span className="rounded-lg border border-line bg-panel2 px-2.5 py-1 text-[11px] tabular-nums text-muted">
          {labels.page} {page} {labels.of} {pages}
        </span>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => onPageChange(page + 1)}
          disabled={page >= pages}
          aria-label={labels.next}
        >
          <span className="hidden sm:inline">{labels.next}</span>
          <ChevronRight className="h-4 w-4 rtl:hidden" />
          <ChevronLeft className="hidden h-4 w-4 rtl:block" />
        </Button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ Misc */

export function Avatar({ name, size = "md" }: { name?: string | null; size?: "sm" | "md" | "lg" }) {
  const sizes = { sm: "h-7 w-7 text-[10px]", md: "h-9 w-9 text-[11px]", lg: "h-12 w-12 text-sm" };
  return (
    <span
      className={cn(
        "grid shrink-0 place-items-center rounded-full bg-gradient-to-br from-accent/80 to-accent2/70 font-semibold text-white shadow-inner",
        sizes[size]
      )}
      title={name || "NEXUS"}
    >
      {initials(name)}
    </span>
  );
}

export function CopyButton({ value, label }: { value: string; label?: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        const ok = await copyText(value);
        if (ok) {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1500);
        }
      }}
      className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-panel2 px-2 py-1 text-[10px] text-muted transition hover:text-ink focus-ring"
    >
      {copied ? <Check className="h-3 w-3 text-ok" /> : <Copy className="h-3 w-3" />}
      {label || (copied ? t("common.copied") : t("common.copy"))}
    </button>
  );
}

export function KeyValue({
  label,
  value,
  className,
  mono
}: {
  label: ReactNode;
  value: ReactNode;
  className?: string;
  mono?: boolean;
}) {
  return (
    <div className={cn("min-w-0", className)}>
      <dt className="text-[10px] font-medium uppercase tracking-[0.1em] text-faint">{label}</dt>
      <dd className={cn("mt-1 break-words text-xs text-ink", mono && "font-mono text-[11px]")}>{value || "—"}</dd>
    </div>
  );
}

export function InlineAlert({
  title,
  children,
  tone = "warning",
  icon: Icon = AlertTriangle,
  className
}: {
  title?: ReactNode;
  children: ReactNode;
  tone?: "info" | "warning" | "danger" | "success";
  icon?: LucideIcon;
  className?: string;
}) {
  const tones = {
    info: "border-sky-400/20 bg-sky-400/[0.06] text-sky-200",
    warning: "border-amber-400/20 bg-amber-400/[0.06] text-amber-200",
    danger: "border-rose-400/20 bg-rose-400/[0.06] text-rose-200",
    success: "border-emerald-400/20 bg-emerald-400/[0.06] text-emerald-200"
  };
  return (
    <div className={cn("flex items-start gap-3 rounded-xl border p-3.5", tones[tone], className)}>
      <Icon className="mt-0.5 h-4 w-4 shrink-0 opacity-90" />
      <div className="min-w-0 text-xs leading-relaxed">
        {title ? <p className="mb-1 font-semibold text-ink">{title}</p> : null}
        <div className="opacity-80">{children}</div>
      </div>
    </div>
  );
}

export function SegmentedControl<T extends string>({
  value,
  onChange,
  options,
  size = "md"
}: {
  value: T;
  onChange: (value: T) => void;
  options: { value: T; label: ReactNode; icon?: LucideIcon }[];
  size?: "sm" | "md";
}) {
  return (
    <div className="inline-flex items-center rounded-xl border border-line bg-panel2 p-0.5">
      {options.map((option) => {
        const Icon = option.icon;
        return (
          <button
            key={option.value}
            type="button"
            onClick={() => onChange(option.value)}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-lg font-medium transition focus-ring",
              size === "sm" ? "px-2.5 py-1 text-[10px]" : "px-3 py-1.5 text-xs",
              value === option.value ? "bg-panel3 text-ink shadow-sm" : "text-muted hover:text-ink"
            )}
          >
            {Icon ? <Icon className="h-3.5 w-3.5" /> : null}
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
