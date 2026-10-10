import React, { useState } from 'react'
import SeverityBadge from '../components/SeverityBadge'
import FindingsPanel from '../components/FindingsPanel'
import AttackGraphPanel from '../components/AttackGraphPanel'
import { submitScan, listScans, getScan } from '../api/client'

const SAMPLE_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: ['iam:PassRole', 'ec2:RunInstances'],
      Resource: '*',
    },
  ],
}, null, 2)

export default function ScannerPage() {
  const [policyJson, setPolicyJson] = useState(SAMPLE_POLICY)
  const [scanTitle, setScanTitle] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('findings')

  const handleScan = async () => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      let parsed
      try {
        parsed = JSON.parse(policyJson)
      } catch {
        throw new Error('Invalid JSON. Check your policy document format.')
      }
      const payload = {
        title: scanTitle || 'Manual Scan',
        policy_json: JSON.stringify(parsed),
      }
      const res = await submitScan(payload)
      setResult(res.data)
      setActiveTab('findings')
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }

  const riskColor = (score) => {
    if (score >= 8) return 'text-red-400'
    if (score >= 5) return 'text-orange-400'
    if (score >= 2) return 'text-yellow-400'
    return 'text-green-400'
  }

  return (
    <div className="min-h-screen bg-slate-900 p-6">
      <div className="max-w-6xl mx-auto space-y-6">

        {/* Header */}
        <div className="border-b border-slate-700 pb-4">
          <h1 className="text-2xl font-bold text-white">IAM Vulnerability Scanner</h1>
          <p className="text-slate-400 text-sm mt-1">
            Paste an AWS IAM policy JSON to detect privilege escalation vectors and attack paths.
          </p>
        </div>

        {/* Input Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-3">
            <label className="block text-sm font-medium text-slate-300">Scan Title (optional)</label>
            <input
              type="text"
              value={scanTitle}
              onChange={(e) => setScanTitle(e.target.value)}
              placeholder="e.g. Production IAM Audit"
              className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
            />
            <label className="block text-sm font-medium text-slate-300">IAM Policy JSON</label>
            <textarea
              value={policyJson}
              onChange={(e) => setPolicyJson(e.target.value)}
              rows={16}
              className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm font-mono text-slate-200 focus:outline-none focus:border-blue-500 resize-none"
              spellCheck={false}
            />
            <button
              onClick={handleScan}
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold py-2.5 rounded-lg transition-colors text-sm"
            >
              {loading ? 'Scanning...' : 'Run Scan'}
            </button>
            {error && (
              <div className="bg-red-950 border border-red-700 text-red-300 text-sm rounded-lg px-4 py-3">
                {error}
              </div>
            )}
          </div>

          {/* Results Section */}
          <div className="space-y-3">
            {result ? (
              <>
                {/* Risk Summary */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
                    <p className={`text-3xl font-bold ${riskColor(result.risk_score)}`}>
                      {result.risk_score?.toFixed(1) ?? 'N/A'}
                    </p>
                    <p className="text-xs text-slate-400 mt-1">Risk Score</p>
                  </div>
                  <div className="bg-slate-800 rounded-lg p-4 border border-slate-700">
                    <p className="text-3xl font-bold text-white">{result.total_vulnerabilities}</p>
                    <p className="text-xs text-slate-400 mt-1">Total Findings</p>
                  </div>
                  <div className="bg-red-950 rounded-lg p-3 border border-red-800">
                    <p className="text-2xl font-bold text-red-300">{result.critical_count}</p>
                    <p className="text-xs text-red-400 mt-1">Critical</p>
                  </div>
                  <div className="bg-orange-950 rounded-lg p-3 border border-orange-800">
                    <p className="text-2xl font-bold text-orange-300">{result.high_count}</p>
                    <p className="text-xs text-orange-400 mt-1">High</p>
                  </div>
                </div>

                {/* Tabs */}
                <div className="flex gap-1 bg-slate-800 rounded-lg p-1">
                  {['findings', 'graph'].map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setActiveTab(tab)}
                      className={`flex-1 text-sm py-1.5 rounded-md font-medium capitalize transition-colors ${
                        activeTab === tab
                          ? 'bg-blue-600 text-white'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {tab === 'findings' ? 'Findings' : 'Attack Graph'}
                    </button>
                  ))}
                </div>

                <div className="max-h-[520px] overflow-y-auto pr-1">
                  {activeTab === 'findings' ? (
                    <FindingsPanel vulnerabilities={result.vulnerabilities} />
                  ) : (
                    <AttackGraphPanel graph={result.graph} />
                  )}
                </div>
              </>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 text-sm border border-dashed border-slate-700 rounded-lg p-8">
                Scan results will appear here.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
