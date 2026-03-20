import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import Header from './Header'
import ErrorBoundary from '../common/ErrorBoundary'

export default function Layout() {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto p-6 bg-surface-primary">
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  )
}
