import Card from "../components/Card.jsx";

export default function Legal({ title }) {
  return (
    <div className="page">
      <div>
        <div className="page-title">{title}</div>
        <div className="page-subtitle">Rechtliche Informationen.</div>
      </div>
      <Card>
        <div className="page-subtitle">Inhalt folgt.</div>
      </Card>
    </div>
  );
}
