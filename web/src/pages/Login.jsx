import { useState } from "react";
import Button from "../components/Button.tsx";
import Input from "../components/Input.tsx";
import Card from "../components/Card.tsx";
import PageLayout from "../components/PageLayout.tsx";
import { useAuth } from "../contexts/AuthContext.jsx";

export default function Login({ onNavigate }) {
  const { login, setAuthError, authError } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setAuthError("");
    try {
      await login(email, password);
      onNavigate("/dashboard");
    } catch (err) {
      setAuthError(err.message || "Anmeldung fehlgeschlagen");
    } finally {
      setBusy(false);
    }
  };

  return (
    <PageLayout title="Anmelden" subtitle="Zugang für Trainer:innen und Staff.">
      <Card>
        <form onSubmit={handleSubmit} style={{ display: "grid", gap: 16 }}>
          <Input
            label="E-Mail"
            name="email"
            type="email"
            placeholder="name@club.de"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
          <Input
            label="Passwort"
            name="password"
            type="password"
            placeholder="Passwort"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
          {authError ? <div className="form-error">{authError}</div> : null}
          <Button type="submit" disabled={busy}>
            {busy ? "Bitte warten..." : "Anmelden"}
          </Button>
        </form>
        <div style={{ marginTop: 16 }}>
          <Button variant="tertiary" onClick={() => onNavigate("/register")}>
            Konto erstellen
          </Button>
        </div>
      </Card>
    </PageLayout>
  );
}
