import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode
} from "react";
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from "lucide-react";
import { cn } from "../lib/utils";

type ToastVariant = "default" | "success" | "error" | "warning";

interface ToastInput {
  title: string;
  description?: string;
  variant?: ToastVariant;
  duration?: number;
}

interface ToastItem extends ToastInput {
  id: number;
}

interface ToastContextValue {
  toast: (input: ToastInput) => number;
  dismiss: (id: number) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const icons = {
  default: Info,
  success: CheckCircle2,
  error: XCircle,
  warning: AlertTriangle
};

const styles: Record<ToastVariant, string> = {
  default: "border-line bg-panel2 text-ink",
  success: "border-emerald-400/25 bg-emerald-500/10 text-emerald-100",
  error: "border-rose-400/25 bg-rose-500/10 text-rose-100",
  warning: "border-amber-400/25 bg-amber-500/10 text-amber-100"
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const counter = useRef(0);

  const dismiss = useCallback((id: number) => {
    setItems((current) => current.filter((item) => item.id !== id));
  }, []);

  const toast = useCallback(
    (input: ToastInput) => {
      counter.current += 1;
      const id = counter.current;
      const item: ToastItem = { ...input, id };
      setItems((current) => [...current.slice(-3), item]);
      const delay = input.duration ?? (input.variant === "error" ? 7000 : 4500);
      window.setTimeout(() => {
        setItems((current) => current.filter((entry) => entry.id !== id));
      }, delay);
      return id;
    },
    []
  );

  const value = useMemo(() => ({ toast, dismiss }), [toast, dismiss]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed inset-x-0 bottom-4 z-[200] flex flex-col items-center gap-2 px-4 sm:bottom-6 sm:items-end sm:pe-6">
        {items.map((item) => {
          const variant = item.variant || "default";
          const Icon = icons[variant];
          return (
            <div
              key={item.id}
              className={cn(
                "pointer-events-auto flex w-full max-w-md animate-fade-in items-start gap-3 rounded-2xl border p-4 shadow-panel backdrop-blur-xl",
                styles[variant]
              )}
              role="status"
            >
              <Icon className="mt-0.5 h-5 w-5 shrink-0 opacity-90" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold">{item.title}</p>
                {item.description ? <p className="mt-1 text-xs leading-relaxed opacity-75">{item.description}</p> : null}
              </div>
              <button
                type="button"
                onClick={() => dismiss(item.id)}
                className="rounded-lg p-1 opacity-60 transition hover:bg-white/10 hover:opacity-100 focus-ring"
                aria-label="Dismiss"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const value = useContext(ToastContext);
  if (!value) throw new Error("useToast must be used inside ToastProvider");
  return value;
}
