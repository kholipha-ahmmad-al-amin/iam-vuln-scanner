import React, { useState } from 'react'
import SeverityBadge from './SeverityBadge'

export default function FindingsPanel({ vulnerabilities = [] }) {
  const [expanded, setExpanded] = useState(null)

  if (!vulnerabilities.length) {
    return (
      <div className="text-slate-400 text-sm text-center py-8">
        No vulnerabilities detected.
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {vulnerabilities.map((v) => (
        <div
          key={v.id}
          className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden"
        >
          <button
            className="w-full text-left px-4 py-3 flex items-center justify-between gap-3 hover:bg-slate-700 transition-colors"
            onClick={() => setExpanded(expanded === v.id ? null : v.id)}
          >
            <div className="flex items-center gap-3 min-w-0">
              <SeverityBadge severity={v.severity} />
              <span className="text-sm font-medium text-slate-100 truncate">{v.title}</span>
            </div>
            <span className="text-xs font-mono text-slate-400 shrink-0">{v.rule_id}</span>
          </button>

          {expanded === v.id && (
            <div className="px-4 pb-4 border-t border-slate-700 pt-3 space-y-2">
              <p className="text-sm text-slate-300">{v.description}</p>
              {v.matched_actions?.length > 0 && (
                <div>
                  <p className="text-xs text-slate-400 mb-1 uppercase tracking-wide">Matched Actions</p>
                  <div className="flex flex-wrap gap-1">
                    {v.matched_actions.map((a) => (
                      <span key={a} className="text-xs bg-slate-900 text-cyan-400 font-mono px-2 py-0.5 rounded border border-slate-600">
                        {a}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {v.remediation && (
                <div>
                  <p className="text-xs text-slate-400 mb-1 uppercase tracking-wide">Remediation</p>
                  <p className="text-sm text-green-300">{v.remediation}</p>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
