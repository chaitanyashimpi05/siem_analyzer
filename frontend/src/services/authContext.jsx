import React, { createContext, useContext, useState, useEffect } from 'react';
import API from './api';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    const savedUser = localStorage.getItem('siem_user');
    return savedUser ? JSON.parse(savedUser) : null;
  });
  const [token, setToken] = useState(() => localStorage.getItem('siem_token') || null);
  const [loading, setLoading] = useState(false);

  const login = async (username, password) => {
    setLoading(true);
    try {
      const res = await API.post('/auth/login', { username, password });
      const { access_token, user: userData } = res.data;
      localStorage.setItem('siem_token', access_token);
      localStorage.setItem('siem_user', JSON.stringify(userData));
      setToken(access_token);
      setUser(userData);
      return { success: true };
    } catch (err) {
      return {
        success: false,
        message: err.response?.data?.detail || 'Login failed. Invalid credentials.'
      };
    } finally {
      setLoading(false);
    }
  };

  const register = async (username, email, password, role = 'Analyst') => {
    setLoading(true);
    try {
      await API.post('/auth/register', { username, email, password, role });
      return await login(username, password);
    } catch (err) {
      return {
        success: false,
        message: err.response?.data?.detail || 'Registration failed.'
      };
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('siem_token');
    localStorage.removeItem('siem_user');
    setToken(null);
    setUser(null);
    window.location.href = '/login';
  };

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated: !!token, login, register, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
