import Card from "../components/Card.jsx";
import InputField from "../components/InputField.jsx";
import Button from "../components/Button.jsx";

export default function TwoFactor() {
  return (
    <div className="page">
      <div>
        <div className="page-title">2‑Faktor‑Bestätigung</div>
        <div className="page-subtitle">Gib deinen Bestätigungscode ein.</div>
      </div>
      <Card>
        <div style={{ display: "grid", gap: 16 }}>
          <InputField label="Code" name="code" placeholder="123456" />
          <Button>Bestätigen</Button>
        </div>
      </Card>
    </div>
  );
}
