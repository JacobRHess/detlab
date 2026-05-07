import { Link, NavLink, Outlet } from "react-router-dom";

import InsightsMenu from "./components/InsightsMenu";
import SplunkSettings from "./components/SplunkSettings";
import { dataset } from "./lib/cases";

function generatedDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 10);
}

export default function App() {
  const generated = generatedDate(dataset.generated_at);
  return (
    <div className="app">
      <header className="site-header">
        <div className="container site-header__inner">
          <Link to="/" className="brand">
            <span className="brand__mark" aria-hidden="true">⌖</span>
            <span className="brand__name">detlab</span>
            <span className="brand__tag">network detection lab</span>
          </Link>
          <nav className="site-nav">
            <NavLink to="/" end>Coverage</NavLink>
            <InsightsMenu />
            <NavLink to="/roadmap">Roadmap</NavLink>
            <NavLink to="/about">About</NavLink>
            <span className="site-nav__divider" aria-hidden="true" />
            <a
              href="https://github.com/JacobRHess/detlab"
              target="_blank"
              rel="noreferrer"
              className="site-nav__external"
            >
              GitHub ↗
            </a>
            <SplunkSettings />
          </nav>
        </div>
      </header>

      <main className="container site-main">
        <Outlet />
      </main>

      <footer className="site-footer">
        <div className="container site-footer__inner">
          <span>
            Built from <a href="https://github.com/JacobRHess/detlab" target="_blank" rel="noreferrer">JacobRHess/detlab</a>
            {generated && <> · data generated {generated}</>}
          </span>
          <span className="muted">MITRE ATT&amp;CK® is a registered trademark of The MITRE Corporation.</span>
        </div>
      </footer>
    </div>
  );
}
