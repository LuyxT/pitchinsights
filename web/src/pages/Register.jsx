import { useEffect, useState } from "react";
import Button from "../components/Button.jsx";
import InputField from "../components/InputField.jsx";
import Card from "../components/Card.jsx";

export default function Register({ onNavigate }) {
  const [csrf, setCsrf] = useState("");

  useEffect(() => {
    fetch("/api/auth/csrf?purpose=register_form")
      .then((res) => res.json())
      .then((data) => setCsrf(data.csrf_token || ""))
      .catch(() => setCsrf(""));
  }, []);

  return (
    <div className="page">
      <div>
        <div className="page-title">Konto erstellen</div>
        <div className="page-subtitle">Lege dein Trainer:innenkonto an.</div>
      </div>
      <Card>
        <form method="post" action="/register" style={{ display: "grid", gap: 16 }}>
          <input type="hidden" name="csrf_token" value={csrf} />
          <input type="hidden" name="invitation_code" />
          <input type="hidden" name="promo_code" />
          <InputField label="E-Mail" name="email" type="email" placeholder="name@club.de" />
          <InputField label="Passwort" name="password" type="password" placeholder="Passwort" />
          <Button type="submit">Konto erstellen</Button>
        </form>
        <div style={{ marginTop: 16 }}>
          <Button variant="tertiary" onClick={() => onNavigate("/login")}>
            Zur Anmeldung
          </Button>
        </div>
      </Card>
    </div>
  );
}
