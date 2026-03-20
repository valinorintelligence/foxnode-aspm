import { useState, useRef, useEffect } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { securityAgentAPI, productsAPI } from '../services/api'
import {
  Bot, Send, User, AlertTriangle, Shield, TrendingUp, Loader2,
  Zap, FileText, Network, ChevronRight, ChevronLeft, X, BarChart3
} from 'lucide-react'

interface Message {
  id: string
  role: 'user' | 'agent'
  content: string
  data?: any
  suggestions?: string[]
  timestamp: Date
}

const QUICK_ACTIONS = [
  { label: 'Top Risks', icon: AlertTriangle, message: 'What are my top risks?' },
  { label: 'Executive Report', icon: FileText, message: 'Generate an executive report' },
  { label: 'Attack Chains', icon: Network, message: 'Show me attack chains' },
  { label: 'What should I fix first?', icon: Zap, message: 'What should I fix first?' },
]

export default function SecurityAgentPage() {
  const [messages, setMessages] = useState<Message[]>([{
    id: '1',
    role: 'agent',
    content: "I'm your AI Security Agent. I can analyze your security posture, identify attack chains, generate executive reports, and answer questions about your vulnerabilities. Select a product or ask me anything!",
    suggestions: ['What are my top risks?', 'Show me attack chains', 'Generate an executive report', 'What should I fix first?'],
    timestamp: new Date(),
  }])
  const [input, setInput] = useState('')
  const [selectedProduct, setSelectedProduct] = useState<number | null>(null)
  const [sidePanelOpen, setSidePanelOpen] = useState(false)
  const [sidePanelData, setSidePanelData] = useState<any>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const { data: products } = useQuery({
    queryKey: ['products'],
    queryFn: () => productsAPI.list(),
  })

  const chatMutation = useMutation({
    mutationFn: (message: string) => securityAgentAPI.chat(message, selectedProduct || undefined),
    onSuccess: (res) => {
      const data = res.data
      const agentMsg: Message = {
        id: Date.now().toString(),
        role: 'agent',
        content: data.response || data.message || JSON.stringify(data),
        data: data.data,
        suggestions: data.suggestions,
        timestamp: new Date(),
      }
      setMessages(prev => [...prev, agentMsg])
      if (data.data) {
        setSidePanelData(data.data)
        setSidePanelOpen(true)
      }
    },
    onError: () => {
      setMessages(prev => [...prev, {
        id: Date.now().toString(),
        role: 'agent',
        content: 'I encountered an error processing your request. Please try again.',
        timestamp: new Date(),
      }])
    },
  })

  const analyzeMutation = useMutation({
    mutationFn: (productId: number) => securityAgentAPI.analyze(productId),
    onSuccess: (res) => {
      const d = res.data
      setMessages(prev => [...prev, {
        id: Date.now().toString(),
        role: 'agent',
        content: d.executive_summary || 'Analysis complete.',
        data: d,
        suggestions: ['Show attack chains', 'Generate full report', 'What should I prioritize?'],
        timestamp: new Date(),
      }])
      setSidePanelData(d)
      setSidePanelOpen(true)
    },
  })

  const attackChainMutation = useMutation({
    mutationFn: (productId: number) => securityAgentAPI.attackChains(productId),
    onSuccess: (res) => {
      const chains = res.data.attack_chains || res.data
      const content = Array.isArray(chains) && chains.length > 0
        ? `Found ${chains.length} potential attack chain(s):\n\n${chains.map((c: any, i: number) =>
            `**${i + 1}. ${c.name}** (Risk: ${c.risk_score}/100)\n${c.description || c.steps?.map((s: any) => `  -> ${s}`).join('\n') || ''}`
          ).join('\n\n')}`
        : 'No attack chains detected. Your findings don\'t form exploitable chains -- that\'s good!'
      setMessages(prev => [...prev, {
        id: Date.now().toString(),
        role: 'agent',
        content,
        data: res.data,
        timestamp: new Date(),
      }])
      setSidePanelData(res.data)
      setSidePanelOpen(true)
    },
  })

  const reportMutation = useMutation({
    mutationFn: (productId: number) => securityAgentAPI.report(productId),
    onSuccess: (res) => {
      setMessages(prev => [...prev, {
        id: Date.now().toString(),
        role: 'agent',
        content: 'Executive report generated successfully. Key highlights are shown in the side panel.',
        data: res.data,
        suggestions: ['What are the top risks?', 'Show remediation steps', 'Analyze attack chains'],
        timestamp: new Date(),
      }])
      setSidePanelData(res.data)
      setSidePanelOpen(true)
    },
  })

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const isLoading = chatMutation.isPending || analyzeMutation.isPending || attackChainMutation.isPending || reportMutation.isPending

  const sendMessage = (text?: string) => {
    const msg = text || input
    if (!msg.trim()) return

    setMessages(prev => [...prev, {
      id: Date.now().toString(),
      role: 'user',
      content: msg,
      timestamp: new Date(),
    }])
    setInput('')

    const lower = msg.toLowerCase()
    if (lower.includes('attack chain') && selectedProduct) {
      attackChainMutation.mutate(selectedProduct)
    } else if ((lower.includes('analyze') || lower.includes('analysis')) && selectedProduct) {
      analyzeMutation.mutate(selectedProduct)
    } else if (lower.includes('executive report') && selectedProduct) {
      reportMutation.mutate(selectedProduct)
    } else {
      chatMutation.mutate(msg)
    }
  }

  const getRiskBadgeColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30'
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
      case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30'
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30'
    }
  }

  return (
    <div className="h-[calc(100vh-6rem)] flex gap-4">
      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 rounded-xl">
              <Bot className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">AI Security Agent</h1>
              <p className="text-gray-400 text-sm">Ask questions about your security posture in natural language</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <select
              className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50"
              value={selectedProduct || ''}
              onChange={(e) => setSelectedProduct(e.target.value ? Number(e.target.value) : null)}
            >
              <option value="">All Products</option>
              {products?.data?.map((p: any) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
            {!sidePanelOpen && sidePanelData && (
              <button
                onClick={() => setSidePanelOpen(true)}
                className="p-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-400 hover:text-white transition-colors"
                title="Open side panel"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Chat Container */}
        <div className="flex-1 bg-gray-800/30 border border-gray-700/50 rounded-xl flex flex-col overflow-hidden">
          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {messages.map((msg) => (
              <div key={msg.id} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : ''}`}>
                {msg.role === 'agent' && (
                  <div className="w-8 h-8 bg-emerald-500/20 rounded-lg flex items-center justify-center shrink-0 mt-1">
                    <Bot className="w-4 h-4 text-emerald-400" />
                  </div>
                )}
                <div className={`max-w-[70%] ${
                  msg.role === 'user'
                    ? 'bg-blue-600/20 border-blue-500/30'
                    : 'bg-gray-800 border-gray-700'
                } border rounded-xl p-4`}>
                  <p className="text-sm text-gray-200 whitespace-pre-wrap">{msg.content}</p>

                  {/* Data tables */}
                  {msg.data && (
                    <div className="mt-3 space-y-2">
                      {msg.data.risk_level && (
                        <div className="flex items-center gap-2">
                          <AlertTriangle className={`w-4 h-4 ${
                            msg.data.risk_level === 'critical' ? 'text-red-400' :
                            msg.data.risk_level === 'high' ? 'text-orange-400' : 'text-yellow-400'
                          }`} />
                          <span className="text-sm font-medium text-white capitalize">
                            Risk Level: {msg.data.risk_level}
                          </span>
                        </div>
                      )}
                      {msg.data.metrics && (
                        <div className="grid grid-cols-3 gap-2 mt-2">
                          {Object.entries(msg.data.metrics).slice(0, 6).map(([key, val]) => (
                            <div key={key} className="bg-gray-900/50 rounded-lg p-2 text-center">
                              <div className="text-xs text-gray-500">{key.replace(/_/g, ' ')}</div>
                              <div className="text-sm font-bold text-white">{String(val)}</div>
                            </div>
                          ))}
                        </div>
                      )}
                      {msg.data.top_risks && msg.data.top_risks.length > 0 && (
                        <div className="mt-2 space-y-1">
                          {msg.data.top_risks.slice(0, 3).map((risk: any, i: number) => (
                            <div key={i} className="flex items-center gap-2 text-xs text-gray-400">
                              <Zap className="w-3 h-3 text-yellow-400" />
                              <span>{risk.title || risk}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Suggestion chips */}
                  {msg.suggestions && (
                    <div className="flex flex-wrap gap-2 mt-3">
                      {msg.suggestions.map((s, i) => (
                        <button
                          key={i}
                          onClick={() => sendMessage(s)}
                          className="text-xs px-3 py-1 bg-gray-700/50 hover:bg-gray-600/50 text-gray-300 rounded-full border border-gray-600/50 transition-colors"
                        >
                          {s}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
                {msg.role === 'user' && (
                  <div className="w-8 h-8 bg-blue-600/20 rounded-lg flex items-center justify-center shrink-0 mt-1">
                    <User className="w-4 h-4 text-blue-400" />
                  </div>
                )}
              </div>
            ))}

            {/* Typing indicator */}
            {isLoading && (
              <div className="flex gap-3">
                <div className="w-8 h-8 bg-emerald-500/20 rounded-lg flex items-center justify-center shrink-0">
                  <Bot className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="bg-gray-800 border border-gray-700 rounded-xl p-4">
                  <div className="flex items-center gap-2">
                    <Loader2 className="w-4 h-4 text-emerald-400 animate-spin" />
                    <span className="text-sm text-gray-400">Analyzing...</span>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Actions + Input */}
          <div className="p-4 border-t border-gray-700/50 space-y-3">
            {/* Quick action buttons */}
            <div className="flex flex-wrap gap-2">
              {QUICK_ACTIONS.map((action) => (
                <button
                  key={action.label}
                  onClick={() => sendMessage(action.message)}
                  disabled={isLoading}
                  className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg border border-gray-700 transition-colors disabled:opacity-50"
                >
                  <action.icon className="w-3.5 h-3.5" />
                  {action.label}
                </button>
              ))}
            </div>

            {/* Input area */}
            <div className="flex gap-3">
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && sendMessage()}
                placeholder="Ask about your security posture..."
                className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-4 py-3 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-emerald-500/50"
                disabled={isLoading}
              />
              <button
                onClick={() => sendMessage()}
                disabled={!input.trim() || isLoading}
                className="px-4 py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-50 transition-colors"
              >
                <Send className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Collapsible Side Panel */}
      {sidePanelOpen && sidePanelData && (
        <div className="w-80 flex flex-col bg-gray-800/50 border border-gray-700/50 rounded-xl overflow-hidden shrink-0">
          {/* Panel Header */}
          <div className="flex items-center justify-between p-4 border-b border-gray-700/50">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white">Analysis Details</h3>
            </div>
            <button
              onClick={() => setSidePanelOpen(false)}
              className="p-1 hover:bg-gray-700 rounded-lg transition-colors"
            >
              <X className="w-4 h-4 text-gray-400" />
            </button>
          </div>

          {/* Panel Content */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {/* Risk Level Badge */}
            {sidePanelData.risk_level && (
              <div className="space-y-2">
                <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Level</h4>
                <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-sm font-medium capitalize ${getRiskBadgeColor(sidePanelData.risk_level)}`}>
                  <Shield className="w-3.5 h-3.5" />
                  {sidePanelData.risk_level}
                </span>
              </div>
            )}

            {/* Key Metrics */}
            {sidePanelData.metrics && (
              <div className="space-y-2">
                <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">Key Metrics</h4>
                <div className="space-y-2">
                  {Object.entries(sidePanelData.metrics).map(([key, val]) => (
                    <div key={key} className="flex items-center justify-between bg-gray-900/50 rounded-lg px-3 py-2">
                      <span className="text-xs text-gray-400 capitalize">{key.replace(/_/g, ' ')}</span>
                      <span className="text-sm font-semibold text-white">{String(val)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Score */}
            {sidePanelData.risk_score != null && (
              <div className="space-y-2">
                <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Score</h4>
                <div className="bg-gray-900/50 rounded-lg p-3 text-center">
                  <div className="text-3xl font-bold text-white">{sidePanelData.risk_score}</div>
                  <div className="text-xs text-gray-500 mt-1">out of 100</div>
                </div>
              </div>
            )}

            {/* Top Risks */}
            {sidePanelData.top_risks && sidePanelData.top_risks.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">Top Risks</h4>
                <div className="space-y-2">
                  {sidePanelData.top_risks.map((risk: any, i: number) => (
                    <div key={i} className="flex items-start gap-2 bg-gray-900/50 rounded-lg p-3">
                      <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 mt-0.5 shrink-0" />
                      <span className="text-xs text-gray-300">{risk.title || risk.name || risk}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Attack Chains */}
            {sidePanelData.attack_chains && sidePanelData.attack_chains.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">Attack Chains</h4>
                <div className="space-y-2">
                  {sidePanelData.attack_chains.map((chain: any, i: number) => (
                    <div key={i} className="bg-gray-900/50 rounded-lg p-3 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium text-white">{chain.name}</span>
                        {chain.risk_score != null && (
                          <span className="text-xs text-red-400 font-semibold">{chain.risk_score}/100</span>
                        )}
                      </div>
                      {chain.description && (
                        <p className="text-xs text-gray-500">{chain.description}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommendations */}
            {sidePanelData.recommendations && sidePanelData.recommendations.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">Recommendations</h4>
                <div className="space-y-2">
                  {sidePanelData.recommendations.map((rec: any, i: number) => (
                    <div key={i} className="flex items-start gap-2 bg-gray-900/50 rounded-lg p-3">
                      <TrendingUp className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                      <span className="text-xs text-gray-300">{rec.text || rec.title || rec}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Executive Summary */}
            {sidePanelData.executive_summary && (
              <div className="space-y-2">
                <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">Executive Summary</h4>
                <p className="text-xs text-gray-300 bg-gray-900/50 rounded-lg p-3 leading-relaxed">
                  {sidePanelData.executive_summary}
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
