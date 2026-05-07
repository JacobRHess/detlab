import React, { lazy, Suspense } from "react";
import ReactDOM from "react-dom/client";
import { HashRouter, Route, Routes } from "react-router-dom";

import App from "./App";
import "./styles.css";

// Lazy-load every route so the home page bundle stays small. CaseDetail in
// particular pulls in react-markdown + the fixture-stats charts only when a
// user opens a case; same goes for the Stats page heatmap.
const Home = lazy(() => import("./pages/Home"));
const Stats = lazy(() => import("./pages/Stats"));
const About = lazy(() => import("./pages/About"));
const CaseDetail = lazy(() => import("./pages/CaseDetail"));
const Roadmap = lazy(() => import("./pages/Roadmap"));
const TacticDetail = lazy(() => import("./pages/TacticDetail"));
const Styles = lazy(() => import("./pages/Styles"));
const KillChain = lazy(() => import("./pages/KillChain"));
const Risk = lazy(() => import("./pages/Risk"));
const ThreatGroups = lazy(() => import("./pages/ThreatGroups"));
const Pyramid = lazy(() => import("./pages/Pyramid"));
const DataSources = lazy(() => import("./pages/DataSources"));
const Macros = lazy(() => import("./pages/Macros"));
const CIM = lazy(() => import("./pages/CIM"));
const Lookups = lazy(() => import("./pages/Lookups"));
const Schedule = lazy(() => import("./pages/Schedule"));

function RouteFallback() {
  return (
    <div className="empty-state" aria-busy="true">
      <p className="muted">Loading…</p>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <HashRouter>
      <Routes>
        <Route element={<App />}>
          <Route
            index
            element={
              <Suspense fallback={<RouteFallback />}>
                <Home />
              </Suspense>
            }
          />
          <Route
            path="case/:caseId"
            element={
              <Suspense fallback={<RouteFallback />}>
                <CaseDetail />
              </Suspense>
            }
          />
          <Route
            path="stats"
            element={
              <Suspense fallback={<RouteFallback />}>
                <Stats />
              </Suspense>
            }
          />
          <Route
            path="roadmap"
            element={
              <Suspense fallback={<RouteFallback />}>
                <Roadmap />
              </Suspense>
            }
          />
          <Route
            path="tactic/:slug"
            element={
              <Suspense fallback={<RouteFallback />}>
                <TacticDetail />
              </Suspense>
            }
          />
          <Route
            path="styles"
            element={
              <Suspense fallback={<RouteFallback />}>
                <Styles />
              </Suspense>
            }
          />
          <Route
            path="about"
            element={
              <Suspense fallback={<RouteFallback />}>
                <About />
              </Suspense>
            }
          />
          <Route
            path="kill-chain"
            element={
              <Suspense fallback={<RouteFallback />}>
                <KillChain />
              </Suspense>
            }
          />
          <Route
            path="risk"
            element={
              <Suspense fallback={<RouteFallback />}>
                <Risk />
              </Suspense>
            }
          />
          <Route
            path="threat-groups"
            element={
              <Suspense fallback={<RouteFallback />}>
                <ThreatGroups />
              </Suspense>
            }
          />
          <Route
            path="pyramid"
            element={
              <Suspense fallback={<RouteFallback />}>
                <Pyramid />
              </Suspense>
            }
          />
          <Route
            path="data-sources"
            element={
              <Suspense fallback={<RouteFallback />}>
                <DataSources />
              </Suspense>
            }
          />
          <Route
            path="macros"
            element={
              <Suspense fallback={<RouteFallback />}>
                <Macros />
              </Suspense>
            }
          />
          <Route
            path="cim"
            element={
              <Suspense fallback={<RouteFallback />}>
                <CIM />
              </Suspense>
            }
          />
          <Route
            path="lookups"
            element={
              <Suspense fallback={<RouteFallback />}>
                <Lookups />
              </Suspense>
            }
          />
          <Route
            path="schedule"
            element={
              <Suspense fallback={<RouteFallback />}>
                <Schedule />
              </Suspense>
            }
          />
        </Route>
      </Routes>
    </HashRouter>
  </React.StrictMode>,
);
