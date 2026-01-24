export default function Card({ children, interactive = false, onClick }) {
  return (
    <div className={`card${interactive ? " interactive" : ""}`} onClick={onClick}>
      {children}
    </div>
  );
}
