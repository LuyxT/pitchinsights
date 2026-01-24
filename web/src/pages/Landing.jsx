import Button from "../components/Button.jsx";
import Card from "../components/Card.jsx";

export default function Landing({ onNavigate }) {
  return (
    <div className="page">
      <div>
        <div className="page-title">Pitch Insights</div>
        <div className="page-subtitle">Planung, Kommunikation und Analyse in einem klaren System.</div>
      </div>
      <Card>
        <div className="section-title">Schneller Einstieg</div>
        <div style={{ marginTop: 16, display: "flex", gap: 12 }}>
          <Button onClick={() => onNavigate("/login")}>Anmelden</Button>
          <Button variant="secondary" onClick={() => onNavigate("/register")}>Konto erstellen</Button>
        </div>
      </Card>
    </div>
  );
}
