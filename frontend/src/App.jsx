import { useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'

import Layout from './components/Layout'
import AlertDetailPage from './pages/AlertDetailPage'
import AlertsPage from './pages/AlertsPage'
import DashboardPage from './pages/DashboardPage'
import DetectionsPage from './pages/DetectionsPage'
import EventsPage from './pages/EventsPage'
import LoginPage from './pages/LoginPage'
import SettingsPage from './pages/SettingsPage'
import { api, authStore } from './services/api'

function ProtectedRoute({ user, children }) {
  if (!authStore.getToken()) {
    return <Navigate to="/login" replace />
  }

  if (!user) {
    return <div className="min-h-screen bg-slate-950 p-10 text-slate-100">Loading session...</div>
  }

  return <Layout user={user}>{children}</Layout>
}

export default function App() {
  const [user, setUser] = useState(null)

  async function refreshUser() {
    if (!authStore.getToken()) {
      setUser(null)
      return
    }

    try {
      const identity = await api.me()
      setUser(identity)
    } catch {
      authStore.clear()
      setUser(null)
    }
  }

  useEffect(() => {
    if (!authStore.getToken()) {
      return
    }

    let mounted = true
    api
      .me()
      .then((identity) => {
        if (mounted) {
          setUser(identity)
        }
      })
      .catch(() => {
        authStore.clear()
        if (mounted) {
          setUser(null)
        }
      })

    return () => {
      mounted = false
    }
  }, [])

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage onAuthenticated={refreshUser} />} />
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute user={user}>
              <DashboardPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/events"
          element={
            <ProtectedRoute user={user}>
              <EventsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/alerts"
          element={
            <ProtectedRoute user={user}>
              <AlertsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/alerts/:alertId"
          element={
            <ProtectedRoute user={user}>
              <AlertDetailPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/detections"
          element={
            <ProtectedRoute user={user}>
              <DetectionsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/settings"
          element={
            <ProtectedRoute user={user}>
              <SettingsPage />
            </ProtectedRoute>
          }
        />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
