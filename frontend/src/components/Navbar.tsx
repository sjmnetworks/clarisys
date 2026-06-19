import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function Navbar() {
  const { user, logout, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  if (!isAuthenticated) return null;

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <span className="navbar-logo">C</span>
        Clarisys
      </div>
      <div className="navbar-links">
        <NavLink to="/" end>Dashboard</NavLink>
        {(user?.role === "admin" || user?.role === "auditor") && (
          <NavLink to="/audit">Audit</NavLink>
        )}
        <NavLink to="/history">History</NavLink>
        <NavLink to="/guide">Guide</NavLink>
        {user?.role === "admin" && (
          <NavLink to="/admin">Admin</NavLink>
        )}
      </div>
      <div className="navbar-user">
        {user?.tenant_name && (
          <span className="navbar-tenant">{user.tenant_name}</span>
        )}
        <span className="navbar-username">{user?.username}</span>
        <span className="navbar-role">{user?.role}</span>
        <button className="btn-link" onClick={handleLogout}>Sign out</button>
      </div>
    </nav>
  );
}
