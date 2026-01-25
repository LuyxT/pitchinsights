export default function Badge({ children, tone = "default" }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
