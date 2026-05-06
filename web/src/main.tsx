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
            path="about"
            element={
              <Suspense fallback={<RouteFallback />}>
                <About />
              </Suspense>
            }
          />
        </Route>
      </Routes>
    </HashRouter>
  </React.StrictMode>,
);
