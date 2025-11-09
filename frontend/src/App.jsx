import { useEffect, useMemo, useRef, useState } from 'react';
import CheckGroup from './components/CheckGroup.jsx';
import ScoreSummary from './components/ScoreSummary.jsx';

const API_BASE_URL = import.meta.env.VITE_API_URL ?? '';

const SECTIONS = [
  { key: 'critical', title: 'Kritische checks', description: 'Moeten altijd in orde zijn (TLS, headers, cookies, formulieren, redirectgedrag).' },
  { key: 'important', title: 'Belangrijke checks', description: 'Veel voorkomende misconfiguraties met impact op veiligheid of uptime.' },
  { key: 'pentest', title: 'Actieve pentest', description: 'Veilige formulierinjecties om XSS/SQL-fouten en WAF-reacties te signaleren.' },
  { key: 'nice_to_have', title: 'Nice to have', description: 'UX/SEO/privacy inzichten die het totaalplaatje verbeteren.' }
];

const SCAN_PHASES = [
  { id: 'warmup', title: 'Verbinding maken', start: 0, description: 'URL checken, DNS en eerste reactie ophalen.' },
  { id: 'crawl', title: 'Site verkennen', start: 20, description: 'Interne links, robots.txt en sitemap doornemen.' },
  { id: 'forms', title: 'Formulieren & login', start: 45, description: 'Velden zoeken waar invoer binnenkomt.' },
  { id: 'security', title: 'Veiligheidschecks', start: 65, description: 'Headers, TLS, cookies en foutmeldingen scannen.' },
  { id: 'pentest', title: 'Actieve probes', start: 78, description: 'Formulieren testen met veilige payloads.' },
  { id: 'report', title: 'Rapport samenstellen', start: 88, description: 'Alles netjes bundelen en scores berekenen.' }
];

const PAGE_LIMITS = {
  min: 20,
  max: 150,
  step: 10,
  default: 50
};

const buildApiUrl = (path) => (API_BASE_URL ? `${API_BASE_URL}${path}` : path);

const buildStreamUrl = (targetUrl, maxPages) => {
  const params = new URLSearchParams({ url: targetUrl });
  if (typeof maxPages === 'number') {
    params.set('max_pages', String(maxPages));
  }
  const base = buildApiUrl(`/api/scan/stream?${params.toString()}`);
  if (base.startsWith('http')) {
    return base;
  }
  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  if (base.startsWith('/')) {
    return `${origin}${base}`;
  }
  return `${origin}/${base}`;
};

const formatPageDescription = (page) => {
  const parts = [];
  if (typeof page.depth === 'number') {
    parts.push(`diepte ${page.depth}`);
  }
  if (page.status_code) {
    parts.push(`status ${page.status_code}`);
  }
  if (page.timestamp) {
    const time = new Date(page.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    parts.push(time);
  }
  return parts.join(' · ') || 'In behandeling';
};

export default function App() {
  const [url, setUrl] = useState('');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [history, setHistory] = useState([]);
  const [maxPagesBudget, setMaxPagesBudget] = useState(PAGE_LIMITS.default);
  const [activeBudget, setActiveBudget] = useState(PAGE_LIMITS.default);
  const [scanPages, setScanPages] = useState([]);
  const [pagesScanned, setPagesScanned] = useState(0);
  const [progress, setProgress] = useState(0);
  const [phaseOverride, setPhaseOverride] = useState(null);
  const eventSourceRef = useRef(null);
  const activeScanUrlRef = useRef('');
  const progressPercent = Math.min(100, Math.round(progress));
  const currentPhaseIndex = useMemo(() => {
    if (phaseOverride) {
      const overrideIndex = SCAN_PHASES.findIndex((phase) => phase.id === phaseOverride);
      if (overrideIndex >= 0) {
        return overrideIndex;
      }
    }
    for (let i = SCAN_PHASES.length - 1; i >= 0; i -= 1) {
      if (progress >= SCAN_PHASES[i].start) {
        return i;
      }
    }
    return 0;
  }, [phaseOverride, progress]);
  const currentPhase = SCAN_PHASES[currentPhaseIndex] ?? SCAN_PHASES[0];

  const closeStream = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  };

  useEffect(() => () => closeStream(), []);

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!url) {
      setError('Voer een geldige URL in (inclusief https://).');
      return;
    }
    setLoading(true);
    setError('');
    setReport(null);
    setScanPages([]);
    setPagesScanned(0);
    setProgress(5);
    setPhaseOverride(null);
    setActiveBudget(maxPagesBudget);
    closeStream();
    const streamTarget = buildStreamUrl(url, maxPagesBudget);
    if (typeof window === 'undefined' || typeof window.EventSource === 'undefined') {
      setError('Deze browser ondersteunt geen live scan updates.');
      setLoading(false);
      return;
    }
    activeScanUrlRef.current = url;
    const stream = new EventSource(streamTarget);
    eventSourceRef.current = stream;

    stream.onmessage = (messageEvent) => {
      try {
        const payload = JSON.parse(messageEvent.data);
        if (payload.type === 'page') {
          setScanPages((prev) => {
            const next = [...prev, payload].slice(-8);
            return next;
          });
          if (typeof payload.count === 'number') {
            setPagesScanned(payload.count);
          } else {
            setPagesScanned((prev) => prev + 1);
          }
          setProgress((prev) => Math.max(prev, payload.progress ?? prev));
          if (typeof payload.budget === 'number') {
            setActiveBudget(payload.budget);
          }
        } else if (payload.type === 'phase') {
          if (payload.phase) {
            setPhaseOverride(payload.phase);
          }
          if (payload.progress) {
            setProgress((prev) => Math.max(prev, payload.progress));
          }
        } else if (payload.type === 'report') {
          const finishedUrl = activeScanUrlRef.current || payload?.report?.meta?.target;
          const pagesCount = payload.report?.meta?.pages_scanned ?? pagesScanned ?? 0;
          const maxBudget = payload.report?.meta?.max_pages_budget ?? activeBudget ?? maxPagesBudget;
          setReport(payload.report);
          setPagesScanned(pagesCount);
          setActiveBudget(maxBudget);
          setHistory((prev) => [
            {
              url: finishedUrl,
              at: new Date().toISOString(),
              status: payload.report?.meta?.status_code,
              finalUrl: payload.report?.meta?.final_url,
              pages: pagesCount,
              budget: maxBudget
            },
            ...prev
          ].slice(0, 5));
          setProgress(100);
          setLoading(false);
          closeStream();
          activeScanUrlRef.current = '';
        } else if (payload.type === 'error') {
          setError(payload.message || 'Scan kon niet worden afgerond.');
          setLoading(false);
          setActiveBudget(maxPagesBudget);
          closeStream();
          activeScanUrlRef.current = '';
        }
      } catch {
        // Ignore malformed events.
      }
    };

    stream.onerror = () => {
      setError('Verbinding met scanservice verbroken.');
      setLoading(false);
      setActiveBudget(maxPagesBudget);
      closeStream();
      activeScanUrlRef.current = '';
    };
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
      pentest: calc(report.pentest),
      nice_to_have: calc(report.nice_to_have)
    };
  }, [report]);

  const score = report?.score;
  const activePages = scanPages;
  const activeIndex = activePages.length > 0 ? activePages.length - 1 : 0;

  return (
    <div className="app-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">WeakPoint</p>
          <h1>Website Security Check</h1>
          <p className="subtitle">
            Plak een URL, druk op scan en ontvang direct een rapport met kritieke, belangrijke, pentest- en nice-to-have verbeterpunten.
            Alle checks gebruiken veilige payloads zonder brute-force of destructieve acties.
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
            <div className="page-budget">
              <div className="page-budget__head">
                <label htmlFor="pageBudget">Max. pagina&apos;s per scan</label>
                <span className="page-budget__value">{maxPagesBudget} pagina&apos;s</span>
              </div>
              <input
                id="pageBudget"
                type="range"
                min={PAGE_LIMITS.min}
                max={PAGE_LIMITS.max}
                step={PAGE_LIMITS.step}
                value={maxPagesBudget}
                onChange={(event) => setMaxPagesBudget(Number(event.target.value))}
                disabled={loading}
              />
              <div className="page-budget__ticks">
                <span>Snelle scan (tot 50)</span>
                <span>Volledige scan (tot 150)</span>
              </div>
              <p className="page-budget__hint">
                Standaard beperken we de crawler tot 50 pagina&apos;s zodat hij niet vastloopt. Verhoog alleen voor grotere sites.
              </p>
            </div>
          </form>
          {loading && (
            <div className="scan-inline-status" role="status" aria-live="polite">
              <div className="scan-inline-status__header">
                <p>Scannen...</p>
                <span>{progressPercent}%</span>
              </div>
              <div className="scan-inline-status__progress" aria-hidden="true">
                <div className="scan-inline-status__progress-value" style={{ width: `${progressPercent}%` }} />
              </div>
              <p className="scan-inline-status__phase">{currentPhase.title}</p>
              <p className="scan-inline-status__copy">{currentPhase.description}</p>
              <p className="scan-inline-status__count">
                Pagina&apos;s gescand: {pagesScanned} / {activeBudget}
              </p>
              {scanPages.length === 0 ? (
                <p className="scan-inline-status__empty">
                  We tonen hier meteen de pagina&apos;s zodra ze binnenkomen.
                </p>
              ) : (
                <ul className="scan-inline-status__list">
                  {activePages.map((item, index) => {
                    const key = item.url
                      ? `${item.url}-${item.timestamp ?? index}`
                      : `${item.id ?? index}-${index}`;
                    return (
                      <li key={key} className={index === activeIndex ? 'is-active' : ''}>
                        <span className="scan-inline-status__url">{item.url ?? item.label}</span>
                        <span className="scan-inline-status__desc">
                          {index === activeIndex && scanPages.length > 0 ? 'Nu bezig · ' : ''}
                          {item.description ?? formatPageDescription(item)}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          )}
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
              <div>
                <p className="label">Pagina budget</p>
                <p className="value">{meta.max_pages_budget}</p>
              </div>
            </div>
          )}
          {score && summaryStats && (
            <ScoreSummary score={score} sections={SECTIONS} sectionStats={summaryStats} />
          )}
        </section>

        {history.length > 0 && (
          <section className="history panel">
            <h2>Laatste scans</h2>
            <ul>
              {history.map((item) => {
                const pagesLabel = typeof item.pages === 'number' ? item.pages : 0;
                const budgetLabel = typeof item.budget === 'number' ? item.budget : '-';
                return (
                  <li key={`${item.url}-${item.at}`}>
                    <span>{new Date(item.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    <span>{item.url}</span>
                    <span className="muted">→ {item.finalUrl ?? '-'}</span>
                    <span className="muted">status {item.status ?? '?'}</span>
                    <span className="muted">{`${pagesLabel} pagina's (budget ${budgetLabel})`}</span>
                  </li>
                );
              })}
            </ul>
          </section>
        )}

        {report ? (
          SECTIONS.map((section) => (
            <CheckGroup
              key={section.key}
              title={section.title}
              description={section.description}
              items={report?.[section.key] ?? []}
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
