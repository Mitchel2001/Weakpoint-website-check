import ResultCard from './ResultCard.jsx';

export default function CheckGroup({ title, description, items = [] }) {
  if (!items.length) {
    return null;
  }

  return (
    <section className="panel">
      <div className="group-header">
        <div>
          <h2>{title}</h2>
          <p className="muted">{description}</p>
        </div>
        <span className="muted">Aantal checks: {items.length}</span>
      </div>
      <div className="result-grid">
        {items.map((item) => (
          <ResultCard key={`${item.id}-${item.title}`} item={item} />
        ))}
      </div>
    </section>
  );
}
