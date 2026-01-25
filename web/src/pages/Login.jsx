import { useEffect, useState } from "react";
import Button from "../components/Button.tsx";
import Input from "../components/Input.tsx";
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

  useEffect(() => {
    document.body.classList.add("login-page");
    return () => {
      document.body.classList.remove("login-page");
    };
  }, []);

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="logo">
          <div className="logo-icon">
            <span className="iconoir-soccer-ball" />
          </div>
          <h1>PitchInsights</h1>
          <p>Dein Fußball-Management System</p>
        </div>

        {authError ? (
          <div className="error-message">
            <span className="iconoir-shield-alert" />
            {authError}
          </div>
        ) : null}

        <form onSubmit={handleSubmit}>
          <div className="honeypot" aria-hidden="true">
            <input type="text" name="website" tabIndex={-1} autoComplete="off" />
            <input type="text" name="phone_number" tabIndex={-1} autoComplete="off" />
            <input type="text" name="fax_number" tabIndex={-1} autoComplete="off" />
          </div>
          <Input
            label="E-Mail"
            name="email"
            type="email"
            placeholder="deine@email.de"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            wrapperClassName="form-group"
          />
          <Input
            label="Passwort"
            name="password"
            type="password"
            placeholder="••••••••"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            wrapperClassName="form-group"
          />
          <Button type="submit" disabled={busy} className="submit-btn">
            {busy ? "Bitte warten..." : "Einloggen"}
          </Button>
        </form>

        <div className="divider">
          <span>oder</span>
        </div>

        <div className="register-link">
          Noch kein Account? <a href="/register">Jetzt registrieren</a>
        </div>
        <div className="home-link">
          <a href="/landing">Zur Homepage</a>
        </div>

        <div className="features">
          <p>Was dich erwartet:</p>
          <div className="features-list">
            <div className="feature-item"><span><span className="iconoir-stats-up-square" /></span> Kader</div>
            <div className="feature-item"><span><span className="iconoir-calendar" /></span> Kalender</div>
            <div className="feature-item"><span><span className="iconoir-message" /></span> Messenger</div>
            <div className="feature-item"><span><span className="iconoir-football-ball" /></span> Taktik</div>
          </div>
        </div>

        <div className="legal-links">
          <a href="/datenschutz">Datenschutz</a>
          <span>|</span>
          <a href="/impressum">Impressum</a>
          <span>|</span>
          <a href="/agb">AGB</a>
        </div>
      </div>
    </div>
  );
}
