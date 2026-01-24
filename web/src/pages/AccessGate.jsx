import Card from "../components/Card.jsx";
import Button from "../components/Button.jsx";
import InputField from "../components/InputField.jsx";

export default function AccessGate() {
  return (
    <div className="page">
      <div>
        <div className="page-title">Zugang erforderlich</div>
        <div className="page-subtitle">Bitte gib deinen Zugriffscode ein.</div>
      </div>
      <Card>
        <div style={{ display: "grid", gap: 16 }}>
          <InputField label="Zugriffscode" placeholder="Code" />
          <Button>Weiter</Button>
        </div>
      </Card>
    </div>
  );
}
