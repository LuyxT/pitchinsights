import Card from "../components/Card.jsx";
import Button from "../components/Button.jsx";
import InputField from "../components/InputField.jsx";
import { useState } from "react";
import { useAuth } from "../contexts/AuthContext.jsx";

export default function AccessGate({ onNavigate }) {
  const { verifyAccess, setAuthError, authError } = useAuth();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setAuthError("");
    try {
      await verifyAccess(code);
      onNavigate?.("/login");
    } catch (err) {
      setAuthError(err.message || "Code ungültig");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <div>
        <div className="page-title">Zugang erforderlich</div>
        <div className="page-subtitle">Bitte gib deinen Zugriffscode ein.</div>
      </div>
      <Card>
        <form onSubmit={handleSubmit} style={{ display: "grid", gap: 16 }}>
          <InputField
            label="Zugriffscode"
            placeholder="Code"
            value={code}
            onChange={(event) => setCode(event.target.value)}
          />
          {authError ? <div className="form-error">{authError}</div> : null}
          <Button type="submit" disabled={busy}>
            {busy ? "Bitte warten..." : "Weiter"}
          </Button>
        </form>
      </Card>
    </div>
  );
}
