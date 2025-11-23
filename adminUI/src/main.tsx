import {createRoot} from "react-dom/client";
import App from "./App";
import "./index.css";
import {DevSupport} from "@react-buddy/ide-toolbox";
import {ComponentPreviews, useInitial} from "./dev";
import { AuthProvider } from "./lib/auth/AuthContext";
import { AuthCallback } from "./components/AuthCallback";

// Simple routing based on pathname
const Root = () => {
  const path = window.location.pathname;
  
  if (path === '/callback') {
    return <AuthCallback />;
  }
  
  return (
    <AuthProvider>
      <App />
    </AuthProvider>
  );
};

createRoot(document.getElementById("root")!).render(
  <DevSupport ComponentPreviews={ComponentPreviews} useInitialHook={useInitial}>
    <Root />
  </DevSupport>
);
  