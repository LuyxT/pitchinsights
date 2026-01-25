export default function Button({ variant = "primary", children, onClick, type = "button", disabled }) {
  return (
    <button type={type} className={`btn ${variant}`} onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}
