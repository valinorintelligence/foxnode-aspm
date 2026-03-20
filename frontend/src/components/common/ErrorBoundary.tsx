import React from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

interface Props {
  children: React.ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export default class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex items-center justify-center h-64">
          <div className="text-center space-y-4">
            <AlertTriangle className="w-12 h-12 text-amber-500 mx-auto" />
            <h3 className="text-lg font-semibold text-content-primary">Something went wrong</h3>
            <p className="text-sm text-content-muted max-w-md">
              {this.state.error?.message || 'An unexpected error occurred while loading this page.'}
            </p>
            <button
              onClick={() => this.setState({ hasError: false, error: null })}
              className="btn-secondary inline-flex items-center gap-2 px-4 py-2"
            >
              <RefreshCw className="w-4 h-4" />
              Try Again
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
