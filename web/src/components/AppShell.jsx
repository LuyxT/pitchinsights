import Sidebar from "./Sidebar.jsx";
import Topbar from "./Topbar.jsx";

export default function AppShell({ children, currentPath, onNavigate, title, meta }) {
  return (
    <div className="app-shell">
      <Sidebar currentPath={currentPath} onNavigate={onNavigate} />
      <div className="content">
        <Topbar title={title} meta={meta} />
        {children}
      </div>
    </div>
  );
}
