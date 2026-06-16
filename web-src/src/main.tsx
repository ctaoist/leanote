import { render } from "solid-js/web";
import { Router, Route } from "@solidjs/router";
import { lazy, type ParentProps } from "solid-js";
import { Toaster } from "./components/ui/Toaster";
import { initTheme } from "./lib/theme";
import "./styles/app.css";

initTheme();

const HomePage = lazy(() => import("./pages/HomePage"));
const LoginPage = lazy(() => import("./pages/LoginPage"));
const RegisterPage = lazy(() => import("./pages/RegisterPage"));
const FindPasswordPage = lazy(() => import("./pages/FindPasswordPage"));
const NotesPage = lazy(() => import("./pages/NotesPage"));
const AdminPage = lazy(() => import("./pages/AdminPage"));
const NotFoundPage = lazy(() => import("./pages/NotFoundPage"));

function RootLayout(props: ParentProps) {
  return (
    <>
      {props.children}
      <Toaster />
    </>
  );
}

const root = document.getElementById("root")!;

render(
  () => (
    <Router root={RootLayout}>
      <Route path="/" component={HomePage} />
      <Route path="/index" component={HomePage} />
      <Route path="/login" component={LoginPage} />
      <Route path="/register" component={RegisterPage} />
      <Route path="/findPassword" component={FindPasswordPage} />
      <Route path={["/note", "/note/:noteId"]} component={NotesPage} />
      <Route path="/admin" component={AdminPage} />
      <Route path="*" component={NotFoundPage} />
    </Router>
  ),
  root
);
