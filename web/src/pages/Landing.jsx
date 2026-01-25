import Button from "../components/Button.tsx";
import Card from "../components/Card.tsx";
import PageLayout from "../components/PageLayout.tsx";

export default function Landing({ onNavigate }) {
  return (
    <PageLayout title="Pitch Insights" subtitle="Planung, Kommunikation und Analyse in einem klaren System.">
      <Card>
        <div className="section-title">Schneller Einstieg</div>
        <div style={{ marginTop: 16, display: "flex", gap: 12 }}>
          <Button onClick={() => onNavigate("/login")}>Anmelden</Button>
          <Button variant="secondary" onClick={() => onNavigate("/register")}>Konto erstellen</Button>
        </div>
      </Card>
    </PageLayout>
  );
}
