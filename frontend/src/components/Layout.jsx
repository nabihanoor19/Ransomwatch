import React, { useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  Activity,
  FileText,
  FolderSearch,
  LayoutDashboard,
  LogOut,
  Menu,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  X,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { dashboardApi } from '../api/services';
import { API_BASE_URL } from '../api/client';

export default function Layout() {
  const { user, isAdmin, logout } = useAuth();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [apiHealthy, setApiHealthy] = useState(null);

  useEffect(() => {
    let active = true;
    const checkHealth = async () => {
      try {
        await dashboardApi.getHealth();
        if (active) setApiHealthy(true);
      } catch {
        if (active) setApiHealthy(false);
      }
    };
    checkHealth();
    const timer = setInterval(checkHealth, 30000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  const navItems = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
    { to: '/monitor', label: 'Folder Monitoring', icon: FolderSearch },
    { to: '/events', label: 'File Events & Threats', icon: Activity },
    { to: '/incidents', label: 'Incident Timeline', icon: ShieldAlert },
    { to: '/reports', label: 'Reports & Export', icon: FileText },
  ];

  return (
    <div className="app-shell">
      {sidebarOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <div className="sidebar-brand">
          <div className="brand-icon">
            <ShieldAlert size={20} />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="brand-title">RansomWatch</div>
            <div className="brand-sub">Early Warning SOC</div>
          </div>
          <button
            type="button"
            className="mobile-menu-btn"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close navigation"
          >
            <X size={16} />
          </button>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-label">Operations</div>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                onClick={() => setSidebarOpen(false)}
              >
                <Icon size={18} />
                <span>{item.label}</span>
              </NavLink>
            );
          })}

          {isAdmin && (
            <>
              <div className="nav-section-label">Administration</div>
              <NavLink
                to="/admin"
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                onClick={() => setSidebarOpen(false)}
              >
                <Sliders size={18} />
                <span>Admin Console</span>
              </NavLink>
            </>
          )}
        </nav>

        <div className="sidebar-footer">
          <div className="user-chip">
            <div style={{ minWidth: 0 }}>
              <div className="user-chip-name">{user?.username || 'User'}</div>
              <div className="user-chip-email">{user?.email || ''}</div>
            </div>
            <span className={`badge ${isAdmin ? 'badge-info' : 'badge-low'}`}>
              {user?.role || 'operator'}
            </span>
          </div>

          <button type="button" className="btn btn-secondary" onClick={handleLogout}>
            <LogOut size={16} />
            Sign Out
          </button>
        </div>
      </aside>

      <div className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <button
              type="button"
              className="mobile-menu-btn"
              onClick={() => setSidebarOpen(true)}
              aria-label="Open navigation"
            >
              <Menu size={18} />
            </button>
            <span style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
              API: <span className="mono">{API_BASE_URL}</span>
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span
              className={`badge ${
                apiHealthy === true
                  ? 'badge-low'
                  : apiHealthy === false
                  ? 'badge-critical'
                  : 'badge-neutral'
              }`}
            >
              <ShieldCheck size={13} />
              {apiHealthy === true
                ? 'Backend Online'
                : apiHealthy === false
                ? 'Backend Offline'
                : 'Checking API'}
            </span>
          </div>
        </header>

        <main className="page-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
