import Button from "./Button.jsx";

export default function Topbar({ title, meta }) {
  return (
    <div className="topbar">
      <div>
        <div className="section-title">{title}</div>
        <div className="topbar-meta">{meta}</div>
      </div>
      <Button variant="secondary">Schnellaktionen</Button>
    </div>
  );
}
