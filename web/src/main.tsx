import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter, Route, Routes } from "react-router-dom";

import App from "./App";
import About from "./pages/About";
import CaseDetail from "./pages/CaseDetail";
import Home from "./pages/Home";
import Stats from "./pages/Stats";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <HashRouter>
      <Routes>
        <Route element={<App />}>
          <Route index element={<Home />} />
          <Route path="case/:caseId" element={<CaseDetail />} />
          <Route path="stats" element={<Stats />} />
          <Route path="about" element={<About />} />
        </Route>
      </Routes>
    </HashRouter>
  </React.StrictMode>,
);
