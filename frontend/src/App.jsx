import { useMemo, useState } from 'react';
import CheckGroup from './components/CheckGroup.jsx';

const API_BASE_URL = import.meta.env.VITE_API_URL ?? '';

const SECTIONS = [
  { key: 'critical', title: 'Kritische checks', description: 'Moeten altijd in orde zijn (TLS, headers, cookies, formulieren, redirectgedrag).' },
  { key: 'important', title: 'Belangrijke checks', description: 'Veel voorkomende misconfiguraties met impact op veiligheid of uptime.' },
  { key: 'nice_to_have', title: 'Nice to have', description: 'UX/SEO/privacy inzichten die het totaalplaatje verbeteren.' }
];

const buildApiUrl = (path) => (API_BASE_URL ? `${API_BASE_URL}${path}` : path);

export default function App() {
  const [url, setUrl] = useState('');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [history, setHistory] = useState([]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!url) {
      setError('Voer een geldige URL in (inclusief https://).');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await fetch(buildApiUrl('/api/scan'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || 'Scan kon niet worden afgerond.');
      }
      const data = await response.json();
      setReport(data);
      setHistory((prev) => [
        {
          url,
          at: new Date().toISOString(),
          status: data?.meta?.status_code,
          finalUrl: data?.meta?.final_url
        },
        ...prev
      ].slice(0, 5));
    } catch (err) {
      setError(err.message || 'Onbekende fout tijdens scannen.');
    } finally {
      setLoading(false);
    }
  };

  const meta = report?.meta;

  const summaryStats = useMemo(() => {
    if (!report) return null;
    const calc = (items = []) => {
      const base = { total: items.length, pass: 0, warn: 0, fail: 0, info: 0 };
      items.forEach((item) => {
        base[item.status] = (base[item.status] || 0) + 1;
      });
      return base;
    };
    return {
      critical: calc(report.critical),
      important: calc(report.important),
      nice: calc(report.nice_to_have)
    };
  }, [report]);

  return (
    <div className="app-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">WeakPoint</p>
          <h1>Website Security Check</h1>
          <p className="subtitle">
            Plak een URL, druk op scan en ontvang direct een rapport met kritieke, belangrijke en nice-to-have verbeterpunten.
            Alle checks zijn niet-intrusief en veilig voor productieomgevingen.
          </p>
        </div>
      </header>

      <main className="page">
        <section className="panel">
          <form className="scan-form" onSubmit={handleSubmit}>
            <label htmlFor="url">Website URL</label>
            <div className="input-row">
              <input
                id="url"
                type="url"
                placeholder="https://voorbeeld.nl"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                required
              />
              <button type="submit" disabled={loading}>
                {loading ? 'Scannen...' : 'Start scan'}
              </button>
            </div>
          </form>
          {error && <p className="error-message">{error}</p>}
          {meta && (
            <div className="meta-grid">
              <div>
                <p className="label">Doel</p>
                <p className="value">{meta.target}</p>
              </div>
              <div>
                <p className="label">Laatste URL</p>
                <p className="value">{meta.final_url}</p>
              </div>
              <div>
                <p className="label">Statuscode</p>
                <p className="value">{meta.status_code}</p>
              </div>
              <div>
                <p className="label">Scan tijd</p>
                <p className="value">{new Date(meta.timestamp).toLocaleString()}</p>
              </div>
            </div>
          )}
          {summaryStats && (
            <div className="summary-row">
              {SECTIONS.map((section) => {
                const stats =
                  section.key === 'critical'
                    ? summaryStats.critical
                    : section.key === 'important'
                      ? summaryStats.important
                      : summaryStats.nice;
                return (
                  <div key={section.key} className="summary-chip">
                    <p className="label">{section.title}</p>
                    <p className="value">
                      {stats.pass}✅ {stats.warn}⚠️ {stats.fail}⛔
                    </p>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {history.length > 0 && (
          <section className="history panel">
            <h2>Laatste scans</h2>
            <ul>
              {history.map((item) => (
                <li key={`${item.url}-${item.at}`}>
                  <span>{new Date(item.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  <span>{item.url}</span>
                  <span className="muted">→ {item.finalUrl ?? '-'}</span>
                  <span className="muted">status {item.status ?? '?'}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        {report ? (
          SECTIONS.map((section) => (
            <CheckGroup
              key={section.key}
              title={section.title}
              description={section.description}
              items={section.key === 'critical' ? report.critical : section.key === 'important' ? report.important : report.nice_to_have}
            />
          ))
        ) : (
          <section className="placeholder panel">
            <p>Voer een URL in om de eerste scan te starten. Resultaten verschijnen hier zodra de API klaar is.</p>
          </section>
        )}
      </main>
    </div>
  );
}
