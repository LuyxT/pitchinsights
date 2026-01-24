import Button from "./Button.jsx";

export default function SectionHeader({ title, actionLabel, onAction, actionVariant = "primary" }) {
  return (
    <div className="section-header">
      <div className="section-title">{title}</div>
      {actionLabel ? (
        <Button variant={actionVariant} onClick={onAction}>
          {actionLabel}
        </Button>
      ) : null}
    </div>
  );
}
