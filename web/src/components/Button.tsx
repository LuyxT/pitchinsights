export default function Button({ variant = "primary", children, onClick, type = "button", disabled, className }) {
  return (
    <button type={type} className={className || `btn ${variant}`} onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}
