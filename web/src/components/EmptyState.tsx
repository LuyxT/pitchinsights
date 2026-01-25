import Button from "./Button.tsx";

export default function EmptyState({ title, description, actionLabel, onAction }) {
  return (
    <div className="empty">
      <div className="section-title">{title}</div>
      <div className="page-subtitle" style={{ marginTop: 8 }}>{description}</div>
      {actionLabel ? (
        <div style={{ marginTop: 16 }}>
          <Button variant="secondary" onClick={onAction}>{actionLabel}</Button>
        </div>
      ) : null}
    </div>
  );
}
