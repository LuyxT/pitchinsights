import SectionHeader from "../components/SectionHeader.jsx";
import Card from "../components/Card.jsx";
import InputField from "../components/InputField.jsx";

export default function Settings() {
  return (
    <div className="page">
      <div>
        <div className="page-title">Einstellungen</div>
        <div className="page-subtitle">Konto und Organisation an einem Ort.</div>
      </div>
      <SectionHeader title="Profil" actionLabel="Speichern" />
      <div className="card-grid">
        <Card>
          <InputField label="Vorname" placeholder="Vorname" />
          <div style={{ height: 16 }} />
          <InputField label="Nachname" placeholder="Nachname" />
        </Card>
        <Card>
          <InputField label="E-Mail" type="email" placeholder="name@club.de" />
          <div style={{ height: 16 }} />
          <InputField label="Rolle" placeholder="Trainer" />
        </Card>
      </div>
    </div>
  );
}
