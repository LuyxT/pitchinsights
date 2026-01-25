import { useEffect, useMemo, useState } from "react";
import Card from "../components/Card.tsx";
import Input from "../components/Input.tsx";
import Button from "../components/Button.tsx";
import LoadingState from "../components/LoadingState.tsx";
import PageLayout from "../components/PageLayout.tsx";
import { fetchJson } from "../lib/api.js";
import { useAuth } from "../contexts/AuthContext.jsx";

export default function Join({ onNavigate }) {
  const { user } = useAuth();
  const [code, setCode] = useState("");
  const [invitation, setInvitation] = useState(null);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);

  const initialCode = useMemo(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get("code") || params.get("token") || "";
  }, []);

  useEffect(() => {
    if (!initialCode) return;
    setCode(initialCode);
  }, [initialCode]);

  useEffect(() => {
    let active = true;
    if (!code) {
      setInvitation(null);
      return;
    }
    async function validate() {
      setLoading(true);
      setStatus("");
      try {
        const data = await fetchJson(`/api/v1/invitations/${code}/validate`);
        if (!active) return;
        setInvitation(data);
      } catch (err) {
        if (!active) return;
        setInvitation(null);
        setStatus(err.message || "Einladung ungültig");
      } finally {
        if (active) setLoading(false);
      }
    }
    validate();
    return () => {
      active = false;
    };
  }, [code]);

  const handleJoin = async () => {
    if (!code) return;
    setStatus("");
    setLoading(true);
    try {
      await fetchJson("/api/v1/teams/join", {
        method: "POST",
        body: JSON.stringify({ invitationCode: code }),
      });
      setStatus("Einladung angenommen");
      onNavigate("/dashboard");
    } catch (err) {
      setStatus(err.message || "Einladung fehlgeschlagen");
    } finally {
      setLoading(false);
    }
  };

  return (
    <PageLayout title="Einladung annehmen" subtitle="Verbinde dein Konto mit dem Team.">
      <Card>
        <div style={{ display: "grid", gap: 16 }}>
          <Input
            label="Einladungscode"
            placeholder="Code"
            value={code}
            onChange={(event) => setCode(event.target.value)}
          />
          {loading ? <LoadingState rows={2} /> : null}
          {invitation ? (
            <div className="page-subtitle">
              Team: {invitation.clubName || invitation.teamName}
            </div>
          ) : null}
          {status ? <div className="page-subtitle">{status}</div> : null}
          {user ? (
            <Button onClick={handleJoin} disabled={loading || !code}>
              Einladung annehmen
            </Button>
          ) : (
            <Button onClick={() => onNavigate("/login")}>
              Zum Login
            </Button>
          )}
        </div>
      </Card>
    </PageLayout>
  );
}
