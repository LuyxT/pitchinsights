import { useEffect, useMemo, useState } from "react";
import AppShell from "./components/AppShell.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Training from "./pages/Training.jsx";
import Players from "./pages/Players.jsx";
import Calendar from "./pages/Calendar.jsx";
import Messages from "./pages/Messages.jsx";
import Polls from "./pages/Polls.jsx";
import Settings from "./pages/Settings.jsx";
import Landing from "./pages/Landing.jsx";
import Login from "./pages/Login.jsx";
import Register from "./pages/Register.jsx";
import Onboarding from "./pages/Onboarding.jsx";
import TeamSelect from "./pages/TeamSelect.jsx";
import Join from "./pages/Join.jsx";
import TwoFactor from "./pages/TwoFactor.jsx";
import Legal from "./pages/Legal.jsx";
import AccessGate from "./pages/AccessGate.jsx";
import PaymentPending from "./pages/PaymentPending.jsx";
import Player from "./pages/Player.jsx";
import LoadingState from "./components/LoadingState.tsx";
import { AuthProvider, useAuth } from "./contexts/AuthContext.jsx";

const routes = {
  "/": { component: Dashboard, title: "Home" },
  "/dashboard": { component: Dashboard, title: "Home" },
  "/training": { component: Training, title: "Trainingsplanung" },
  "/players": { component: Players, title: "Spieler:innen" },
  "/calendar": { component: Calendar, title: "Kalender" },
  "/messages": { component: Messages, title: "Nachrichten" },
  "/polls": { component: Polls, title: "Abstimmungen" },
  "/settings": { component: Settings, title: "Einstellungen" },
  "/landing": { component: Landing, title: "Start" },
  "/login": { component: Login, title: "Anmelden" },
  "/register": { component: Register, title: "Registrieren" },
  "/access-gate": { component: AccessGate, title: "Zugang" },
  "/onboarding": { component: Onboarding, title: "Onboarding" },
  "/team-select": { component: TeamSelect, title: "Team wählen" },
  "/join": { component: Join, title: "Einladung" },
  "/2fa": { component: TwoFactor, title: "2‑Faktor" },
  "/impressum": { component: () => <Legal title="Impressum" />, title: "Impressum" },
  "/datenschutz": { component: () => <Legal title="Datenschutz" />, title: "Datenschutz" },
  "/agb": { component: () => <Legal title="AGB" />, title: "AGB" },
  "/payment-pending": { component: PaymentPending, title: "Zahlung" },
  "/player": { component: Player, title: "Spielerprofil" },
};

const defaultMeta = "Team · Woche 1 · Trainer";

function AppContent() {
  const [path, setPath] = useState(window.location.pathname);
  const { user, loading, accessAllowed } = useAuth();

  const publicRoutes = useMemo(
    () => new Set(["/landing", "/login", "/register", "/access-gate", "/join"]),
    []
  );

  useEffect(() => {
    const onPop = () => setPath(window.location.pathname);
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const navigate = (to) => {
    if (to === path) return;
    window.history.pushState({}, "", to);
    setPath(to);
  };

  useEffect(() => {
    if (loading) return;
    if (!accessAllowed && path !== "/landing" && path !== "/access-gate") {
      navigate("/access-gate");
      return;
    }
    if (!user && !publicRoutes.has(path)) {
      navigate("/login");
      return;
    }
    if (user && (path === "/login" || path === "/register" || path === "/access-gate")) {
      navigate("/dashboard");
    }
  }, [accessAllowed, loading, path, publicRoutes, user]);

  if (loading) {
    return (
      <div className="page">
        <LoadingState title="Lade Daten" description="Wir bereiten deine Inhalte vor." />
      </div>
    );
  }

  if (!accessAllowed && path !== "/landing" && path !== "/access-gate") {
    return (
      <div className="page">
        <AccessGate onNavigate={navigate} />
      </div>
    );
  }

  const route = routes[path] || routes["/"];
  const Page = route.component;

  if (publicRoutes.has(path)) {
    return <Page onNavigate={navigate} />;
  }

  return (
    <AppShell currentPath={path} onNavigate={navigate} title={route.title} meta={defaultMeta}>
      <Page onNavigate={navigate} />
    </AppShell>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
