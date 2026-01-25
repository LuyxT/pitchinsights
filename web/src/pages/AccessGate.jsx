import Card from "../components/Card.tsx";
import Button from "../components/Button.tsx";
import Input from "../components/Input.tsx";
import PageLayout from "../components/PageLayout.tsx";
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
    <PageLayout title="Zugang erforderlich" subtitle="Bitte gib deinen Zugriffscode ein.">
      <Card>
        <form onSubmit={handleSubmit} style={{ display: "grid", gap: 16 }}>
          <Input
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
    </PageLayout>
  );
}
