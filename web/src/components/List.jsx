export default function List({ items }) {
  return (
    <div className="list">
      {items.map((item) => (
        <div key={item.id} className="list-row">
          <div>
            <div>{item.title}</div>
            {item.subtitle ? <div className="page-subtitle">{item.subtitle}</div> : null}
          </div>
          {item.meta ? <div className="status-pill">{item.meta}</div> : null}
        </div>
      ))}
    </div>
  );
}
