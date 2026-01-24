import Card from "../components/Card.jsx";
import SectionHeader from "../components/SectionHeader.jsx";
import EmptyState from "../components/EmptyState.jsx";

export default function Dashboard() {
  const hasData = false;

  return (
    <div className="page">
      <div>
        <div className="page-title">Dashboard</div>
        <div className="page-subtitle">Überblick über Trainings, Spieler:innen und nächste Termine.</div>
      </div>
      <SectionHeader title="Nächste Termine" actionLabel="Neues Training" />
      {hasData ? (
        <div className="card-grid">
          <Card>Training morgen · 18:00</Card>
          <Card>Spiel am Samstag · 15:30</Card>
          <Card>Auswertung offen · 2 Clips</Card>
        </div>
      ) : (
        <EmptyState
          title="Noch keine Termine"
          description="Erstelle dein erstes Training oder einen Spieltermin."
          actionLabel="Neues Training"
        />
      )}
      <SectionHeader title="Kennzahlen" />
      <div className="card-grid">
        <Card>
          <div className="section-title">Trainingsbeteiligung</div>
          <div style={{ marginTop: 8, fontSize: "var(--text-xl)", fontWeight: 700 }}>0%</div>
        </Card>
        <Card>
          <div className="section-title">Verfügbare Spieler:innen</div>
          <div style={{ marginTop: 8, fontSize: "var(--text-xl)", fontWeight: 700 }}>0</div>
        </Card>
        <Card>
          <div className="section-title">Offene Rückmeldungen</div>
          <div style={{ marginTop: 8, fontSize: "var(--text-xl)", fontWeight: 700 }}>0</div>
        </Card>
      </div>
    </div>
  );
}
