export default function PageLayout({ title, subtitle, children }) {
  return (
    <div className="page">
      <div>
        <div className="page-title">{title}</div>
        {subtitle ? <div className="page-subtitle">{subtitle}</div> : null}
      </div>
      {children}
    </div>
  );
}
