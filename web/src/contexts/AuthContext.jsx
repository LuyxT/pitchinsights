import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { accessStatus, clearTokens, fetchMe, login, logout, register, verifyAccess } from "../lib/api.js";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [accessAllowed, setAccessAllowed] = useState(true);
  const [loading, setLoading] = useState(true);
  const [authError, setAuthError] = useState("");

  const refreshSession = useCallback(async () => {
    try {
      const status = await accessStatus();
      setAccessAllowed(Boolean(status.allowed));
      if (!status.allowed) {
        setUser(null);
        setLoading(false);
        return;
      }
      const me = await fetchMe();
      setUser(me.user || me);
    } catch (err) {
      clearTokens();
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshSession();
  }, [refreshSession]);

  const handleLogin = useCallback(async (email, password) => {
    setAuthError("");
    const nextUser = await login(email, password);
    setUser(nextUser);
    return nextUser;
  }, []);

  const handleRegister = useCallback(async (payload) => {
    setAuthError("");
    const nextUser = await register(payload);
    setUser(nextUser);
    return nextUser;
  }, []);

  const handleLogout = useCallback(async () => {
    await logout();
    setUser(null);
  }, []);

  const handleVerifyAccess = useCallback(async (code) => {
    setAuthError("");
    await verifyAccess(code);
    setAccessAllowed(true);
    await refreshSession();
  }, [refreshSession]);

  const value = useMemo(() => ({
    user,
    accessAllowed,
    loading,
    authError,
    setAuthError,
    login: handleLogin,
    register: handleRegister,
    logout: handleLogout,
    verifyAccess: handleVerifyAccess,
    refreshSession,
  }), [user, accessAllowed, loading, authError, handleLogin, handleRegister, handleLogout, handleVerifyAccess, refreshSession]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}
