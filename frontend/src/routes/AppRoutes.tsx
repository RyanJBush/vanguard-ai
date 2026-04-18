import { Navigate, Route, Routes } from 'react-router-dom';

import { AppLayout } from '../components/layout/AppLayout';
import { StatePanel } from '../components/common/StatePanel';
import { useAuth } from '../context/AuthContext';
import { AlertDetailPage } from '../pages/AlertDetailPage';
import { AlertsPage } from '../pages/AlertsPage';
import { DashboardPage } from '../pages/DashboardPage';
import { DetectionsPage } from '../pages/DetectionsPage';
import { EventsPage } from '../pages/EventsPage';
import { LoginPage } from '../pages/LoginPage';
import { SettingsPage } from '../pages/SettingsPage';

function ProtectedLayout() {
  const { token, isLoading } = useAuth();

  if (isLoading) {
    return <StatePanel title="Loading session" description="Restoring analyst context..." />;
  }

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  return <AppLayout />;
}

export function AppRoutes() {
  const { token } = useAuth();

  return (
    <Routes>
      <Route path="/login" element={token ? <Navigate to="/dashboard" replace /> : <LoginPage />} />
      <Route element={<ProtectedLayout />}>

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<AppLayout />}>
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
        <Route path="/detections" element={<DetectionsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
