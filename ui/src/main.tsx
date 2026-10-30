import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { App } from "./App";
import { ErrorBoundary } from "./components";
import { Providers } from "./providers";
// Inter for Latin letters and digits, bundled so an offline intranet needs no font host; Chinese falls back to the system face.
import "@fontsource/inter/latin-400.css";
import "@fontsource/inter/latin-500.css";
import "@fontsource/inter/latin-600.css";
import "@fontsource/inter/latin-700.css";
import "./style.css";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <Providers>
      <ErrorBoundary>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </ErrorBoundary>
    </Providers>
  </React.StrictMode>,
);
