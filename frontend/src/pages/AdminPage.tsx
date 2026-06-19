import { useEffect, useState, useCallback, type FormEvent } from "react";
import { useApi } from "../hooks/useApi";
import { useAuth } from "../context/AuthContext";

interface Member {
  id: string;
  email: string;
  username: string;
  role: string;
  scopes: string[];
}

const ALL_SCOPES = [
  "firewall.admin",
  "firewall.audit",
  "firewall.evaluate",
  "firewall.read",
];

const ROLE_OPTIONS = ["owner", "member"];

export default function AdminPage() {
  const { get, post, put, del } = useApi();
  const { user } = useAuth();
  const [members, setMembers] = useState<Member[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionMsg, setActionMsg] = useState("");

  // Invite form
  const [showInvite, setShowInvite] = useState(false);
  const [invEmail, setInvEmail] = useState("");
  const [invUsername, setInvUsername] = useState("");
  const [invPassword, setInvPassword] = useState("");
  const [inviting, setInviting] = useState(false);

  // Edit modal
  const [editing, setEditing] = useState<Member | null>(null);
  const [editRole, setEditRole] = useState("");
  const [editScopes, setEditScopes] = useState<string[]>([]);
  const [editUsername, setEditUsername] = useState("");
  const [editPassword, setEditPassword] = useState("");
  const [saving, setSaving] = useState(false);

  const loadMembers = useCallback(async () => {
    try {
      const resp = await get("/tenant/members");
      const data = await resp.json();
      setMembers(data.members || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load members");
    } finally {
      setLoading(false);
    }
  }, [get]);

  useEffect(() => {
    loadMembers();
  }, [loadMembers]);

  const flash = (msg: string) => {
    setActionMsg(msg);
    setTimeout(() => setActionMsg(""), 3000);
  };

  const handleInvite = async (e: FormEvent) => {
    e.preventDefault();
    setInviting(true);
    setError("");
    try {
      await post(
        "/tenant/invite",
        JSON.stringify({ email: invEmail, username: invUsername, password: invPassword }),
        "application/json",
      );
      setInvEmail("");
      setInvUsername("");
      setInvPassword("");
      setShowInvite(false);
      flash("User invited successfully");
      await loadMembers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invite failed");
    } finally {
      setInviting(false);
    }
  };

  const openEdit = (m: Member) => {
    setEditing(m);
    setEditRole(m.role);
    setEditScopes([...m.scopes]);
    setEditUsername(m.username);
    setEditPassword("");
    setError("");
  };

  const handleSave = async (e: FormEvent) => {
    e.preventDefault();
    if (!editing) return;
    setSaving(true);
    setError("");
    try {
      const body: Record<string, unknown> = {
        role: editRole,
        scopes: editScopes,
        username: editUsername || undefined,
      };
      if (editPassword) body.password = editPassword;
      await put(
        `/tenant/members/${editing.id}`,
        JSON.stringify(body),
        "application/json",
      );
      setEditing(null);
      flash("User updated successfully");
      await loadMembers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Update failed");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (m: Member) => {
    if (!confirm(`Remove ${m.username} (${m.email}) from this organization?`)) return;
    setError("");
    try {
      await del(`/tenant/members/${m.id}`);
      flash(`${m.username} has been removed`);
      await loadMembers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Remove failed");
    }
  };

  const toggleScope = (scope: string) => {
    setEditScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope],
    );
  };

  if (loading) return <div className="page-card"><p className="loading">Loading...</p></div>;

  return (
    <div className="page-card">
      <div className="page-header">
        <h1>User Management</h1>
        <span className="muted" style={{ fontSize: "0.85rem" }}>
          {user?.tenant_name || "Your organization"}
        </span>
      </div>

      {actionMsg && <div className="form-success">{actionMsg}</div>}
      {error && <div className="form-error">{error}</div>}

      {/* Invite new user */}
      <div style={{ marginBottom: "1.5rem" }}>
        {!showInvite ? (
          <button className="btn-primary" onClick={() => setShowInvite(true)}>
            + Invite User
          </button>
        ) : (
          <form onSubmit={handleInvite} className="admin-invite-form">
            <h3>Invite New Member</h3>
            <div className="admin-form-row">
              <div className="form-group">
                <label>Email</label>
                <input
                  type="email"
                  value={invEmail}
                  onChange={(e) => setInvEmail(e.target.value)}
                  placeholder="user@company.com"
                  required
                />
              </div>
              <div className="form-group">
                <label>Username</label>
                <input
                  type="text"
                  value={invUsername}
                  onChange={(e) => setInvUsername(e.target.value)}
                  placeholder="Display name"
                  required
                  minLength={2}
                />
              </div>
              <div className="form-group">
                <label>Password</label>
                <input
                  type="password"
                  value={invPassword}
                  onChange={(e) => setInvPassword(e.target.value)}
                  placeholder="Min. 8 characters"
                  required
                  minLength={8}
                />
              </div>
            </div>
            <div className="admin-form-actions">
              <button type="submit" className="btn-primary" disabled={inviting}>
                {inviting ? "Sending..." : "Send Invite"}
              </button>
              <button type="button" className="btn-link" onClick={() => setShowInvite(false)}>
                Cancel
              </button>
            </div>
          </form>
        )}
      </div>

      {/* Members table */}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Email</th>
              <th>Role</th>
              <th>Scopes</th>
              <th style={{ width: "140px" }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {members.map((m) => (
              <tr key={m.id}>
                <td>
                  <strong>{m.username}</strong>
                  {m.id === user?.sub && (
                    <span className="badge ok" style={{ marginLeft: 6 }}>you</span>
                  )}
                </td>
                <td>{m.email}</td>
                <td>
                  <span className={`badge ${m.role === "owner" ? "ok" : "info"}`}>
                    {m.role}
                  </span>
                </td>
                <td>
                  <div className="scope-tags">
                    {m.scopes.map((s) => (
                      <span key={s} className="scope-tag">{s.replace("firewall.", "")}</span>
                    ))}
                  </div>
                </td>
                <td>
                  <button className="btn-sm btn-outline" onClick={() => openEdit(m)}>
                    Edit
                  </button>
                  {m.id !== user?.sub && (
                    <button
                      className="btn-sm btn-danger"
                      onClick={() => handleDelete(m)}
                      style={{ marginLeft: 6 }}
                    >
                      Remove
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {members.length === 0 && (
              <tr>
                <td colSpan={5} className="muted" style={{ textAlign: "center" }}>
                  No members found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Edit modal */}
      {editing && (
        <div className="modal-backdrop" onClick={() => setEditing(null)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <h2>Edit User</h2>
            <p className="muted">{editing.email}</p>
            <form onSubmit={handleSave}>
              <div className="form-group">
                <label>Username</label>
                <input
                  type="text"
                  value={editUsername}
                  onChange={(e) => setEditUsername(e.target.value)}
                  minLength={2}
                />
              </div>
              <div className="form-group">
                <label>Role</label>
                <select value={editRole} onChange={(e) => setEditRole(e.target.value)}>
                  {ROLE_OPTIONS.map((r) => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>Scopes</label>
                <div className="scope-checkboxes">
                  {ALL_SCOPES.map((s) => (
                    <label key={s} className="checkbox-label">
                      <input
                        type="checkbox"
                        checked={editScopes.includes(s)}
                        onChange={() => toggleScope(s)}
                      />
                      {s.replace("firewall.", "")}
                    </label>
                  ))}
                </div>
              </div>
              <div className="form-group">
                <label>New Password <span className="muted">(leave blank to keep current)</span></label>
                <input
                  type="password"
                  value={editPassword}
                  onChange={(e) => setEditPassword(e.target.value)}
                  placeholder="Min. 8 characters"
                  minLength={8}
                />
              </div>
              {error && <div className="form-error">{error}</div>}
              <div className="admin-form-actions">
                <button type="submit" className="btn-primary" disabled={saving}>
                  {saving ? "Saving..." : "Save Changes"}
                </button>
                <button type="button" className="btn-link" onClick={() => setEditing(null)}>
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
