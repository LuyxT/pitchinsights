import Button from "./Button.tsx";
import { useAuth } from "../contexts/AuthContext.jsx";

export default function Topbar({ title, meta }) {
  const { user, logout } = useAuth();
  const userLabel = user ? [user.vorname, user.nachname].filter(Boolean).join(" ") : "";

  return (
    <div className="topbar">
      <div>
        <div className="section-title">{title}</div>
        <div className="topbar-meta">{meta}</div>
      </div>
      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        {userLabel ? <div className="page-subtitle">{userLabel}</div> : null}
        <Button variant="secondary" onClick={logout}>
          Abmelden
        </Button>
      </div>
    </div>
  );
}
