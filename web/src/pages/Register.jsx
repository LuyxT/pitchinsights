import { useState } from "react";
import Button from "../components/Button.tsx";
import Input from "../components/Input.tsx";
import Card from "../components/Card.tsx";
import PageLayout from "../components/PageLayout.tsx";
import { useAuth } from "../contexts/AuthContext.jsx";

export default function Register({ onNavigate }) {
  const { register, setAuthError, authError } = useAuth();
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setAuthError("");
    try {
      await register({
        email,
        password,
        firstName,
        lastName,
      });
      onNavigate("/dashboard");
    } catch (err) {
      setAuthError(err.message || "Registrierung fehlgeschlagen");
    } finally {
      setBusy(false);
    }
  };

  return (
    <PageLayout title="Konto erstellen" subtitle="Lege dein Trainer:innenkonto an.">
      <Card>
        <form onSubmit={handleSubmit} style={{ display: "grid", gap: 16 }}>
          <Input
            label="Vorname"
            name="firstName"
            placeholder="Vorname"
            value={firstName}
            onChange={(event) => setFirstName(event.target.value)}
          />
          <Input
            label="Nachname"
            name="lastName"
            placeholder="Nachname"
            value={lastName}
            onChange={(event) => setLastName(event.target.value)}
          />
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
            {busy ? "Bitte warten..." : "Konto erstellen"}
          </Button>
        </form>
        <div style={{ marginTop: 16 }}>
          <Button variant="tertiary" onClick={() => onNavigate("/login")}>
            Zur Anmeldung
          </Button>
        </div>
      </Card>
    </PageLayout>
  );
}
