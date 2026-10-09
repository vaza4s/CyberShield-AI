import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";\n\nif ("serviceWorker" in navigator) {\n  navigator.serviceWorker.getRegistrations().then((registrations) => {\n    registrations.forEach((registration) => registration.unregister());\n  }).catch(() => {});\n}

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
