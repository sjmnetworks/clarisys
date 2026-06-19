import { Navigate } from "react-router-dom";
import { useAuth, type Role } from "../context/AuthContext";
import type { ReactNode } from "react";

interface Props {
  children: ReactNode;
  roles?: Role[];
}

export default function ProtectedRoute({ children, roles }: Props) {
  const { isAuthenticated, user } = useAuth();

  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (roles && user && !roles.includes(user.role)) {
    return (
      <div className="page-card">
        <h1>Access denied</h1>
        <p>Your role ({user.role}) does not have permission to view this page.</p>
      </div>
    );
  }

  return <>{children}</>;
}
