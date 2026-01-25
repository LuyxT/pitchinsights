import Sidebar from "./Sidebar.tsx";
import Topbar from "./Topbar.tsx";

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
