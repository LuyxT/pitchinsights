import Card from "../components/Card.jsx";
import InputField from "../components/InputField.jsx";
import Button from "../components/Button.jsx";

export default function Join() {
  return (
    <div className="page">
      <div>
        <div className="page-title">Einladung annehmen</div>
        <div className="page-subtitle">Verbinde dein Konto mit dem Team.</div>
      </div>
      <Card>
        <div style={{ display: "grid", gap: 16 }}>
          <InputField label="E-Mail" name="email" type="email" placeholder="name@club.de" />
          <InputField label="Passwort" name="password" type="password" placeholder="Passwort" />
          <Button>Einladung annehmen</Button>
        </div>
      </Card>
    </div>
  );
}
