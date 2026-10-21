/* NEXUS UI kit — cohesive primitives used across all screens.
   These components intentionally depend only on the global NEXUS CSS design
   system (styles.css), so pages stay readable and theme/RTL switching is free. */

import {
  useEffect,
  type HTMLAttributes,
  type ReactNode,
} from 'react';
import { cn } from '../lib/utils';
import i18n from '../lib/i18n';

/* ------------------------------------------------------------------ Card */

export interface CardProps extends Omit<HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  hover?: boolean;
}

export function Card({ title, subtitle, actions, hover, className, children, ...rest }: CardProps) {
  return (
    <div className={cn('card', hover && 'card-hover', className)} {...rest}>
      {(title || subtitle || actions) && (
        <div className="card-header">
          <div>
            {title && <div className="card-title">{title}</div>}
            {subtitle && <div className="card-subtitle">{subtitle}</div>}
          </div>
          {actions}
        </div>
      )}
      {children}
    </div>
  );
}

/* ----------------------------------------------------------------- Badge */

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  kind?: string;
}

export function Badge({ kind = 'info', className, children, ...rest }: BadgeProps) {
  const tone = String(kind || 'info').toLowerCase().replace(/\s+/g, '_');
  return (
    <span className={cn('badge', tone, className)} {...rest}>
      {children}
    </span>
  );
}

/* --------------------------------------------------------------- Spinner */

export function Spinner({ label, className }: { label?: ReactNode; className?: string }) {
  return (
    <div className={cn('loading-wrap', className)} role="status" aria-live="polite">
      <div className="spinner" aria-hidden="true" />
      {label && <div className="text-small text-muted">{label}</div>}
    </div>
  );
}

/* -------------------------------------------------------------- Progress */

export function Progress({ value, className }: { value: number; className?: string }) {
  const width = Math.max(0, Math.min(100, Number.isFinite(value) ? value : 0));
  return (
    <div
      className={cn('progress', className)}
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(width)}
    >
      <div className="progress-bar" style={{ width: `${width}%` }} />
    </div>
  );
}

/* ------------------------------------------------------------- StatCard */

export interface StatCardProps {
  icon?: ReactNode;
  tone?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'neutral' | string;
  value: ReactNode;
  label: ReactNode;
  delta?: ReactNode;
  className?: string;
}

export function StatCard({ icon, tone = 'neutral', value, label, delta, className }: StatCardProps) {
  return (
    <div className={cn('stat-card', className)}>
      {icon != null && (
        <div className={cn('stat-icon', tone)} aria-hidden="true">
          {icon}
        </div>
      )}
      <div style={{ minWidth: 0 }}>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
        {delta && <div className="stat-delta">{delta}</div>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------ EmptyState */

export interface EmptyStateProps {
  icon?: ReactNode;
  title?: ReactNode;
  desc?: ReactNode;
  action?: ReactNode;
  className?: string;
}

export function EmptyState({ icon = '◇', title, desc, action, className }: EmptyStateProps) {
  return (
    <div className={cn('empty-state', className)}>
      {icon != null && <div className="empty-state-icon" aria-hidden="true">{icon}</div>}
      {title && <div className="empty-state-title">{title}</div>}
      {desc && <div className="empty-state-desc">{desc}</div>}
      {action && <div style={{ marginTop: 14 }}>{action}</div>}
    </div>
  );
}

/* ------------------------------------------------------------- FieldError */

export function FieldError({ message, className }: { message?: ReactNode; className?: string }) {
  if (!message) return null;
  return (
    <div className={cn('form-error', className)} role="alert">
      {message}
    </div>
  );
}

/* -------------------------------------------------------------- Pagination */

export interface PaginationProps {
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
  className?: string;
}

export function Pagination({ page, pageSize, total, onPage, className }: PaginationProps) {
  const pages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)));
  const current = Math.min(Math.max(1, page), pages);
  if (pages <= 1) return null;
  return (
    <div
      className={cn('flex items-center justify-between', className)}
      style={{ marginTop: 16, gap: 10, flexWrap: 'wrap' }}
    >
      <span className="text-small text-muted">
        {current} / {pages}
      </span>
      <div className="flex gap-2">
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={() => onPage(current - 1)}
          disabled={current <= 1}
          aria-label="Previous page"
        >
          ‹
        </button>
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={() => onPage(current + 1)}
          disabled={current >= pages}
          aria-label="Next page"
        >
          ›
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ Modal */

export interface ModalProps {
  title?: ReactNode;
  onClose: () => void;
  footer?: ReactNode;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  children?: ReactNode;
}

export function Modal({ title, onClose, footer, size = 'md', className, children }: ModalProps) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = previous;
    };
  }, [onClose]);

  return (
    <div
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className={cn('modal', size === 'lg' && 'modal-lg', className)}
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === 'string' ? title : undefined}
      >
        <div className="modal-header">
          <div>{title}</div>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={onClose}
            aria-label={i18n.t('close')}
          >
            ×
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  );
}

/* ---------------------------------------------------------- ConfirmDialog */

export interface ConfirmDialogProps {
  title: ReactNode;
  message: ReactNode;
  onConfirm: () => void;
  onCancel: () => void;
  danger?: boolean;
}

export function ConfirmDialog({ title, message, onConfirm, onCancel, danger }: ConfirmDialogProps) {
  return (
    <Modal
      title={title}
      onClose={onCancel}
      footer={
        <>
          <button type="button" className="btn btn-ghost" onClick={onCancel}>
            {i18n.t('cancel')}
          </button>
          <button
            type="button"
            className={cn('btn', danger ? 'btn-danger' : 'btn-primary')}
            onClick={onConfirm}
          >
            {i18n.t('confirm')}
          </button>
        </>
      }
    >
      <div className="text-small" style={{ color: 'var(--txt-1)' }}>{message}</div>
    </Modal>
  );
}
