import Card from "../components/Card.jsx";
import SectionHeader from "../components/SectionHeader.jsx";
import InputField from "../components/InputField.jsx";

export default function Onboarding() {
  return (
    <div className="page">
      <div>
        <div className="page-title">Onboarding</div>
        <div className="page-subtitle">Grunddaten für dein Team.</div>
      </div>
      <SectionHeader title="Teamdetails" actionLabel="Speichern" />
      <div className="card-grid">
        <Card>
          <InputField label="Vereinsname" placeholder="Club" />
          <div style={{ height: 16 }} />
          <InputField label="Mannschaft" placeholder="1. Mannschaft" />
        </Card>
        <Card>
          <InputField label="Saison" placeholder="2024/25" />
          <div style={{ height: 16 }} />
          <InputField label="Rolle" placeholder="Trainer" />
        </Card>
      </div>
    </div>
  );
}
