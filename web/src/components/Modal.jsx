import Button from "./Button.jsx";

export default function Modal({ title, description, confirmLabel, cancelLabel, onConfirm, onCancel }) {
  return (
    <div className="modal-backdrop">
      <div className="modal">
        <div className="section-title">{title}</div>
        <div className="page-subtitle" style={{ marginTop: 8 }}>{description}</div>
        <div style={{ display: "flex", gap: 12, marginTop: 24 }}>
          <Button variant="secondary" onClick={onCancel}>{cancelLabel}</Button>
          <Button variant="primary" onClick={onConfirm}>{confirmLabel}</Button>
        </div>
      </div>
    </div>
  );
}
