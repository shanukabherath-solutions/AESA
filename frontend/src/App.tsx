import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { AuditLogs } from "./pages/AuditLogs";
import { CICD } from "./pages/CICD";
import { ChangeReview } from "./pages/ChangeReview";
import { Changes } from "./pages/Changes";
import { Dashboard } from "./pages/Dashboard";
import { Login } from "./pages/Login";
import { RepositoryPage } from "./pages/Repository";
import { TaskDetail } from "./pages/TaskDetail";
import { Tasks } from "./pages/Tasks";
import { useAuth } from "./services/auth";

export default function App() {
  const { user, loading } = useAuth();
  if (loading) return <p className="p-8 text-dim">Loading…</p>;
  if (!user) return <Login />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="repository" element={<RepositoryPage />} />
        <Route path="tasks" element={<Tasks />} />
        <Route path="tasks/:id" element={<TaskDetail />} />
        <Route path="changes" element={<Changes />} />
        <Route path="changes/:id" element={<ChangeReview />} />
        <Route path="audit" element={<AuditLogs />} />
        <Route path="cicd" element={<CICD />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
