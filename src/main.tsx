import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { DashboardClient } from "@/app/dashboard/ui/DashboardClient";
import "@/app/globals.css";

function App(): React.ReactElement {
  if (window.location.pathname === "/") {
    window.history.replaceState(null, "", "/dashboard");
  }
  return <DashboardClient />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
