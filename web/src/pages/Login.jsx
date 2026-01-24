import { useEffect, useState } from "react";
import Button from "../components/Button.jsx";
import InputField from "../components/InputField.jsx";
import Card from "../components/Card.jsx";

export default function Login({ onNavigate }) {
  const [csrf, setCsrf] = useState("");

  useEffect(() => {
    fetch("/api/auth/csrf?purpose=login_form")
      .then((res) => res.json())
      .then((data) => setCsrf(data.csrf_token || ""))
      .catch(() => setCsrf(""));
  }, []);

  return (
    <div className="page">
      <div>
        <div className="page-title">Anmelden</div>
        <div className="page-subtitle">Zugang für Trainer:innen und Staff.</div>
      </div>
      <Card>
        <form method="post" action="/login" style={{ display: "grid", gap: 16 }}>
          <input type="hidden" name="csrf_token" value={csrf} />
          <InputField label="E-Mail" name="email" type="email" placeholder="name@club.de" />
          <InputField label="Passwort" name="password" type="password" placeholder="Passwort" />
          <Button type="submit">Anmelden</Button>
        </form>
        <div style={{ marginTop: 16 }}>
          <Button variant="tertiary" onClick={() => onNavigate("/register")}>
            Konto erstellen
          </Button>
        </div>
      </Card>
    </div>
  );
}
