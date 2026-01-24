import { useState } from "react";
import Button from "../components/Button.jsx";
import InputField from "../components/InputField.jsx";
import Card from "../components/Card.jsx";
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
    <div className="page">
      <div>
        <div className="page-title">Konto erstellen</div>
        <div className="page-subtitle">Lege dein Trainer:innenkonto an.</div>
      </div>
      <Card>
        <form onSubmit={handleSubmit} style={{ display: "grid", gap: 16 }}>
          <InputField
            label="Vorname"
            name="firstName"
            placeholder="Vorname"
            value={firstName}
            onChange={(event) => setFirstName(event.target.value)}
          />
          <InputField
            label="Nachname"
            name="lastName"
            placeholder="Nachname"
            value={lastName}
            onChange={(event) => setLastName(event.target.value)}
          />
          <InputField
            label="E-Mail"
            name="email"
            type="email"
            placeholder="name@club.de"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
          <InputField
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
    </div>
  );
}
