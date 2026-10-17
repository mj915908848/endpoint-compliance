import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { App } from "./App";
import { ErrorBoundary } from "./components";
import { Providers } from "./providers";
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
