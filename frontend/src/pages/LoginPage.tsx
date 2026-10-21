import { useEffect, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  ArrowRight,
  CheckCircle2,
  Eye,
  EyeOff,
  Fingerprint,
  Globe2,
  Loader2,
  LockKeyhole,
  Moon,
  Radar,
  ShieldCheck,
  Sun,
  Users
} from "lucide-react";
import { ApiError } from "../lib/api";
import { cn } from "../lib/utils";
import { useAuth } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";
import { toggleLanguage } from "../lib/i18n";
import { Logo } from "../components/Logo";
import { Button, Field, InlineAlert, Input } from "../components/ui";
import { useDocumentTitle } from "../hooks";

type Mode = "login" | "bootstrap";

export default function LoginPage() {
  const { t, i18n } = useTranslation();
  const { user, login, bootstrap, loading, bootstrapRequired, bootstrapEmail } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const [mode, setMode] = useState<Mode>(bootstrapRequired ? "bootstrap" : "login");
  const [email, setEmail] = useState(bootstrapEmail || localStorage.getItem("nexus.last_email") || "");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [suggestions, setSuggestions] = useState<string[]>([]);

  useDocumentTitle(t("auth.signIn"));

  useEffect(() => {
    if (bootstrapRequired) {
      setMode("bootstrap");
      if (bootstrapEmail) setEmail((current) => current || bootstrapEmail);
    }
  }, [bootstrapRequired, bootstrapEmail]);

  if (!loading && user) {
    const target = (location.state as { from?: string } | null)?.from || "/dashboard";
    return <Navigate to={target} replace />;
  }

  const onChangeMode = () => {
    setMode(mode === "login" ? "bootstrap" : "login");
    setError("");
    setMfaRequired(false);
  };

  const submitLogin = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    setSuggestions([]);
    setSubmitting(true);
    try {
      await login(email, password, mfaRequired ? totp : undefined);
      localStorage.setItem("nexus.last_email", email.trim().toLowerCase());
      navigate("/dashboard", { replace: true });
    } catch (caught) {
      if (caught instanceof ApiError) {
        if (caught.code === "mfa_required" || caught.code === "invalid_mfa_code") {
          setMfaRequired(true);
          setError(caught.message);
        } else {
          setError(caught.message || t("auth.invalidCredentials"));
        }
        const detailSuggestions = caught.detail?.suggestions;
        if (Array.isArray(detailSuggestions)) setSuggestions(detailSuggestions.map(String));
      } else {
        setError(caught instanceof Error ? caught.message : t("toasts.connection"));
      }
    } finally {
      setSubmitting(false);
    }
  };

  const submitBootstrap = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");
    setFieldErrors({});
    const errors: Record<string, string> = {};
    if (fullName.trim().length < 2) errors.fullName = t("common.required");
    if (!email.includes("@")) errors.email = t("auth.emailPlaceholder");
    if (password.length < 12) errors.password = t("auth.strongPassword");
    if (password !== confirmPassword) errors.confirmPassword = t("profile.passwordMismatch");
    if (Object.keys(errors).length) {
      setFieldErrors(errors);
      return;
    }
    setSubmitting(true);
    try {
      await bootstrap(email, fullName, password);
      navigate("/dashboard", { replace: true });
    } catch (caught) {
      if (caught instanceof ApiError) {
        setError(caught.message);
        const detailSuggestions = caught.detail?.suggestions;
        if (Array.isArray(detailSuggestions)) setSuggestions(detailSuggestions.map(String));
      } else {
        setError(caught instanceof Error ? caught.message : t("toasts.connection"));
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="relative flex min-h-screen bg-bg">
      <div className="absolute inset-x-0 top-0 z-20 flex items-center justify-between px-4 py-4 sm:px-6">
        <div className="flex items-center gap-2 lg:hidden">
          <Logo size={30} />
          <span className="font-display text-sm font-bold tracking-[0.2em] text-ink">NEXUS</span>
        </div>
        <div className="ms-auto flex items-center gap-1">
          <button
            type="button"
            onClick={toggleTheme}
            className="grid h-9 w-9 place-items-center rounded-xl border border-line/70 bg-panel/50 text-muted backdrop-blur transition hover:text-ink focus-ring"
            aria-label={t("common.theme")}
          >
            {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
          <button
            type="button"
            onClick={() => toggleLanguage()}
            className="flex h-9 items-center gap-1.5 rounded-xl border border-line/70 bg-panel/50 px-2.5 text-[10px] font-semibold text-muted backdrop-blur transition hover:text-ink focus-ring"
            aria-label={t("common.language")}
          >
            <Globe2 className="h-3.5 w-3.5" />
            {i18n.language.startsWith("ar") ? "EN" : "ع"}
          </button>
        </div>
      </div>

      <section className="relative hidden w-[54%] overflow-hidden border-e border-line/50 lg:flex lg:flex-col">
        <div className="absolute inset-0 cyber-grid opacity-70" />
        <div className="glow-orb left-[10%] top-[5%] h-72 w-72 bg-accent/25" />
        <div className="glow-orb bottom-[5%] right-[5%] h-80 w-80 bg-accent2/15" />
        <div className="absolute inset-0 bg-gradient-to-br from-transparent via-bg/20 to-bg/80" />

        <div className="relative flex items-center gap-3 px-10 pt-9">
          <Logo size={42} />
          <div>
            <p className="font-display text-lg font-bold tracking-[0.2em] text-ink">NEXUS</p>
            <p className="text-[8px] font-semibold uppercase tracking-[0.32em] text-accent2">
              {t("app.tagline")}
            </p>
          </div>
        </div>

        <div className="relative flex flex-1 flex-col justify-center px-10 xl:px-16">
          <div className="max-w-xl">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-accent/20 bg-accent/[0.07] px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.15em] text-accent">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute h-full w-full animate-ping rounded-full bg-accent opacity-60" />
                <span className="relative h-1.5 w-1.5 rounded-full bg-accent" />
              </span>
              {t("auth.secureAccess")}
            </div>
            <h1 className="font-display text-[clamp(2rem,3.2vw,3.4rem)] font-semibold leading-[1.05] tracking-[-0.035em] text-ink">
              {t("auth.headline")}
            </h1>
            <p className="mt-5 max-w-lg text-sm leading-relaxed text-muted">{t("auth.subheadline")}</p>

            <div className="mt-8 space-y-3">
              {[
                { icon: Radar, text: t("auth.bulletEngines") },
                { icon: ShieldCheck, text: t("auth.bulletSoc") },
                { icon: Globe2, text: t("auth.bulletArabic") }
              ].map((item) => (
                <div key={item.text} className="flex items-center gap-3">
                  <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg border border-line bg-panel/60 text-accent2">
                    <item.icon className="h-3.5 w-3.5" />
                  </span>
                  <span className="text-xs text-muted">{item.text}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="pointer-events-none absolute inset-y-0 end-8 my-auto hidden h-[340px] w-[340px] items-center justify-center xl:flex">
            <div className="absolute inset-0 rounded-full border border-accent/10" />
            <div className="absolute inset-10 rounded-full border border-accent/10" />
            <div className="absolute inset-20 rounded-full border border-accent2/10" />
            <div className="absolute inset-0 overflow-hidden rounded-full">
              <div className="radar-sweep h-full w-full opacity-70" />
            </div>
            <div className="absolute h-px w-full bg-line/30" />
            <div className="absolute h-full w-px bg-line/30" />
            {[
              { top: "24%", left: "64%" },
              { top: "58%", left: "35%" },
              { top: "70%", left: "68%" },
              { top: "38%", left: "32%" }
            ].map((position, index) => (
              <span
                key={index}
                className="absolute h-1.5 w-1.5 rounded-full bg-accent2 shadow-[0_0_12px_2px_rgba(34,211,238,.4)]"
                style={position}
              />
            ))}
            <div className="relative grid h-20 w-20 place-items-center rounded-full border border-accent/30 bg-accent/10 backdrop-blur">
              <Logo size={44} />
            </div>
          </div>
        </div>

        <div className="relative flex items-center justify-between border-t border-line/40 px-10 py-5 text-[9px] uppercase tracking-[0.14em] text-faint">
          <span className="flex items-center gap-2">
            <LockKeyhole className="h-3 w-3" /> {t("auth.loginFootnote")}
          </span>
          <span className="font-mono">{t("footer.version")} 1.0</span>
        </div>
      </section>

      <section className="relative flex flex-1 items-center justify-center px-4 py-20 sm:px-8">
        <div className="w-full max-w-[420px] animate-fade-in">
          <div className="mb-8 hidden items-center gap-3 lg:flex lg:opacity-0">
            <Logo size={40} />
          </div>

          <div className="login-panel rounded-2xl border border-line/80 p-6 sm:p-8">
            <div className="mb-6">
              <div className="mb-3 grid h-11 w-11 place-items-center rounded-xl border border-accent/20 bg-accent/10 text-accent">
                <Fingerprint className="h-5 w-5" />
              </div>
              <h2 className="font-display text-xl font-semibold tracking-tight text-ink">
                {mode === "bootstrap" ? t("auth.bootstrapTitle") : t("auth.welcomeBack")}
              </h2>
              <p className="mt-1.5 text-xs leading-relaxed text-muted">
                {mode === "bootstrap" ? t("auth.bootstrapSubtitle") : t("auth.loginSubtitle")}
              </p>
            </div>

            {mode === "bootstrap" ? (
              <form onSubmit={submitBootstrap} className="space-y-4">
                <InlineAlert title={t("auth.bootstrapTitle")} tone="info" icon={Users}>
                  {t("auth.bootstrapInfo")}
                </InlineAlert>
                <Field label={t("auth.fullName")} required>
                  <Input
                    value={fullName}
                    onChange={(event) => setFullName(event.target.value)}
                    placeholder={t("auth.fullName")}
                    autoComplete="name"
                    autoFocus
                  />
                  {fieldErrors.fullName ? <span className="text-[10px] text-danger">{fieldErrors.fullName}</span> : null}
                </Field>
                <Field label={t("auth.ownerEmail")} required>
                  <Input
                    type="email"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    placeholder="owner@company.com"
                    autoComplete="email"
                  />
                  {fieldErrors.email ? <span className="text-[10px] text-danger">{fieldErrors.email}</span> : null}
                </Field>
                <Field label={t("common.password")} required hint={t("auth.strongPassword")}>
                  <div className="relative">
                    <Input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      className="pe-10"
                      autoComplete="new-password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((current) => !current)}
                      className="absolute end-2 top-1/2 grid h-7 w-7 -translate-y-1/2 place-items-center rounded-lg text-faint hover:text-ink"
                      aria-label={showPassword ? t("auth.hidePassword") : t("auth.showPassword")}
                    >
                      {showPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                  {fieldErrors.password ? <span className="text-[10px] text-danger">{fieldErrors.password}</span> : null}
                </Field>
                <Field label={t("profile.confirmPassword")} required>
                  <Input
                    type={showPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                    autoComplete="new-password"
                  />
                  {fieldErrors.confirmPassword ? (
                    <span className="text-[10px] text-danger">{fieldErrors.confirmPassword}</span>
                  ) : null}
                </Field>
                {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
                <Button type="submit" size="lg" className="w-full" loading={submitting}>
                  {submitting ? t("auth.creatingOwner") : t("auth.createOwner")}
                  {!submitting ? <ArrowRight className="h-4 w-4 rtl:flip-x" /> : null}
                </Button>
                <p className="text-center text-[10px] leading-relaxed text-faint">{t("auth.bootstrapNote")}</p>
              </form>
            ) : (
              <form onSubmit={submitLogin} className="space-y-4">
                <Field label={t("auth.email")}>
                  <Input
                    type="email"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    placeholder={t("auth.emailPlaceholder")}
                    autoComplete="username"
                    autoFocus
                    required
                  />
                </Field>
                <Field label={t("auth.password")}>
                  <div className="relative">
                    <Input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      placeholder={t("auth.passwordPlaceholder")}
                      autoComplete="current-password"
                      className="pe-10"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((current) => !current)}
                      className="absolute end-2 top-1/2 grid h-7 w-7 -translate-y-1/2 place-items-center rounded-lg text-faint hover:text-ink"
                      aria-label={showPassword ? t("auth.hidePassword") : t("auth.showPassword")}
                    >
                      {showPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </Field>

                {mfaRequired ? (
                  <div className="animate-fade-in">
                    <Field label={t("auth.mfaCode")} hint={t("auth.mfaHint")}>
                      <Input
                        value={totp}
                        onChange={(event) => setTotp(event.target.value.replace(/\D/g, "").slice(0, 6))}
                        placeholder={t("auth.mfaPlaceholder")}
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        className="text-center font-mono text-lg tracking-[0.5em]"
                        autoFocus
                        required
                      />
                    </Field>
                  </div>
                ) : null}

                {error ? (
                  <InlineAlert tone={mfaRequired ? "warning" : "danger"}>
                    {mfaRequired ? t("auth.mfaRequired") : error}
                  </InlineAlert>
                ) : null}
                {suggestions.length ? (
                  <ul className="list-inside list-disc space-y-1 rounded-lg border border-line bg-panel2/60 p-3 text-[10px] text-muted">
                    {suggestions.map((suggestion) => (
                      <li key={suggestion}>{suggestion}</li>
                    ))}
                  </ul>
                ) : null}

                <Button type="submit" size="lg" className="w-full" loading={submitting}>
                  {submitting ? t("auth.signingIn") : t("auth.signInBtn")}
                  {!submitting ? <ArrowRight className="h-4 w-4 rtl:flip-x" /> : null}
                </Button>

                <div className="flex items-center justify-center gap-1.5 pt-1 text-[9px] text-faint">
                  <LockKeyhole className="h-3 w-3" />
                  {t("auth.loginFootnote")}
                </div>
              </form>
            )}
          </div>

          <div className="mt-5 flex items-center justify-center gap-4 text-[9px] text-faint">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="h-3 w-3 text-emerald-400/70" /> JWT
            </span>
            <span className="h-3 w-px bg-line/70" />
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="h-3 w-3 text-emerald-400/70" /> TOTP
            </span>
            <span className="h-3 w-px bg-line/70" />
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="h-3 w-3 text-emerald-400/70" /> Audit
            </span>
          </div>

          {loading ? (
            <div className="mt-5 flex items-center justify-center gap-2 text-[10px] text-muted">
              <Loader2 className="h-3 w-3 animate-spin" />
              {t("common.loading")}
            </div>
          ) : null}

          {mode === "login" && !bootstrapRequired ? (
            <p className="mt-6 text-center text-[10px] leading-relaxed text-faint">{t("auth.demoHint")}</p>
          ) : null}
          {mode === "bootstrap" ? (
            <button
              type="button"
              onClick={onChangeMode}
              className="mt-5 block w-full text-center text-[10px] text-faint underline-offset-4 hover:text-muted hover:underline"
            >
              {t("auth.signIn")}
            </button>
          ) : null}
        </div>
      </section>
    </div>
  );
}
