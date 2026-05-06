import { Link, NavLink, Outlet } from "react-router-dom";

import { dataset } from "./lib/cases";

export default function App() {
  const generated = new Date(dataset.generated_at);
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
            <NavLink to="/stats">Stats</NavLink>
            <NavLink to="/about">About</NavLink>
            <a href="https://github.com/JacobRHess/detlab" target="_blank" rel="noreferrer">
              GitHub ↗
            </a>
          </nav>
        </div>
      </header>

      <main className="container site-main">
        <Outlet />
      </main>

      <footer className="site-footer">
        <div className="container site-footer__inner">
          <span>
            Built from <a href="https://github.com/JacobRHess/detlab" target="_blank" rel="noreferrer">JacobRHess/detlab</a>{" "}
            · data generated {generated.toISOString().slice(0, 10)}
          </span>
          <span className="muted">MITRE ATT&amp;CK® is a registered trademark of The MITRE Corporation.</span>
        </div>
      </footer>
    </div>
  );
}
