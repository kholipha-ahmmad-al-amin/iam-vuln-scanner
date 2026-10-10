import React from 'react'

const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-900 text-red-200 border border-red-700',
  HIGH: 'bg-orange-900 text-orange-200 border border-orange-700',
  MEDIUM: 'bg-yellow-900 text-yellow-200 border border-yellow-700',
  LOW: 'bg-blue-900 text-blue-200 border border-blue-700',
}

export default function SeverityBadge({ severity }) {
  const style = SEVERITY_STYLES[severity] || 'bg-slate-700 text-slate-300'
  return (
    <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${style}`}>
      {severity}
    </span>
  )
}
