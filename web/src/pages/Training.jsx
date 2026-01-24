import SectionHeader from "../components/SectionHeader.jsx";
import Card from "../components/Card.jsx";
import InputField from "../components/InputField.jsx";
import Button from "../components/Button.jsx";

export default function Training() {
  return (
    <div className="page">
      <div>
        <div className="page-title">Trainingsplanung</div>
        <div className="page-subtitle">Schritte klar strukturieren und logisch gruppieren.</div>
      </div>
      <SectionHeader title="Neues Training" actionLabel="Speichern" />
      <div className="card-grid">
        <Card>
          <div className="section-title">Datum & Zeit</div>
          <div style={{ display: "grid", gap: 16, marginTop: 16 }}>
            <InputField label="Datum" type="date" />
            <InputField label="Uhrzeit" type="time" />
          </div>
        </Card>
        <Card>
          <div className="section-title">Übungen</div>
          <div style={{ display: "grid", gap: 16, marginTop: 16 }}>
            <InputField label="Schwerpunkt" placeholder="z. B. Umschalten" />
            <InputField label="Notizen" placeholder="Optionale Details" />
          </div>
        </Card>
        <Card>
          <div className="section-title">Spieler:innen</div>
          <div style={{ marginTop: 16 }}>
            <Button variant="secondary">Kader auswählen</Button>
          </div>
        </Card>
        <Card>
          <div className="section-title">Notizen</div>
          <div style={{ marginTop: 16 }}>
            <InputField label="Notizen" placeholder="Kurz und klar" />
          </div>
        </Card>
      </div>
    </div>
  );
}
