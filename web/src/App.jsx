import { useEffect, useState } from "react";
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

const routes = {
  "/": { component: Dashboard, title: "Dashboard" },
  "/training": { component: Training, title: "Trainingsplanung" },
  "/players": { component: Players, title: "Spieler:innen" },
  "/calendar": { component: Calendar, title: "Kalender" },
  "/messages": { component: Messages, title: "Nachrichten" },
  "/polls": { component: Polls, title: "Abstimmungen" },
  "/settings": { component: Settings, title: "Einstellungen" },
  "/landing": { component: Landing, title: "Start" },
  "/login": { component: Login, title: "Anmelden" },
  "/register": { component: Register, title: "Registrieren" },
  "/onboarding": { component: Onboarding, title: "Onboarding" },
  "/team-select": { component: TeamSelect, title: "Team wählen" },
  "/join": { component: Join, title: "Einladung" },
  "/2fa": { component: TwoFactor, title: "2‑Faktor" },
  "/impressum": { component: () => <Legal title="Impressum" />, title: "Impressum" },
  "/datenschutz": { component: () => <Legal title="Datenschutz" />, title: "Datenschutz" },
  "/agb": { component: () => <Legal title="AGB" />, title: "AGB" },
  "/access-gate": { component: AccessGate, title: "Zugang" },
  "/payment-pending": { component: PaymentPending, title: "Zahlung" },
  "/player": { component: Player, title: "Spielerprofil" },
};

const defaultMeta = "Team · Woche 1 · Trainer";

export default function App() {
  const [path, setPath] = useState(window.location.pathname);

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

  const route = routes[path] || routes["/"];
  const Page = route.component;

  return (
    <AppShell currentPath={path} onNavigate={navigate} title={route.title} meta={defaultMeta}>
      <Page onNavigate={navigate} />
    </AppShell>
  );
}
