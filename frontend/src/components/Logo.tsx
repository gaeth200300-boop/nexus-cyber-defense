import { cn } from "../lib/utils";

export function Logo({ size = 38, className }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn("shrink-0", className)}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id="nexus-logo-grad" x1="8" y1="8" x2="56" y2="56" gradientUnits="userSpaceOnUse">
          <stop stopColor="#a78bfa" />
          <stop offset="0.52" stopColor="#8b5cf6" />
          <stop offset="1" stopColor="#22d3ee" />
        </linearGradient>
        <linearGradient id="nexus-logo-core" x1="22" y1="22" x2="42" y2="42" gradientUnits="userSpaceOnUse">
          <stop stopColor="#eef0f8" />
          <stop offset="1" stopColor="#a5f3fc" />
        </linearGradient>
      </defs>
      <path
        d="M32 4.8 54.8 18v28L32 59.2 9.2 46V18L32 4.8Z"
        stroke="url(#nexus-logo-grad)"
        strokeWidth="2.2"
        fill="rgba(139,92,246,0.06)"
      />
      <path
        d="M32 11 49.2 21v22L32 53 14.8 43V21L32 11Z"
        stroke="rgba(139,92,246,0.22)"
        strokeWidth="0.8"
      />
      <path
        d="M22.5 43V21l19 22V21"
        stroke="url(#nexus-logo-core)"
        strokeWidth="3.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="32" cy="32" r="2.4" fill="#22d3ee" />
      <circle cx="32" cy="32" r="5" stroke="rgba(34,211,238,0.24)" strokeWidth="0.8" />
      <path d="M32 1.5v5M32 57.5v5M1.5 32h5M57.5 32h5" stroke="rgba(139,92,246,0.5)" strokeWidth="0.8" />
    </svg>
  );
}

export function LogoMark({ className }: { className?: string }) {
  return (
    <span className={cn("relative inline-grid place-items-center", className)}>
      <span className="absolute inset-0 rounded-2xl bg-accent/20 blur-xl" />
      <Logo size={40} className="relative" />
    </span>
  );
}
