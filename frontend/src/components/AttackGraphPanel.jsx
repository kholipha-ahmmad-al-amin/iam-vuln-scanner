import React from 'react'

const NODE_COLORS = {
  PRINCIPAL: '#3b82f6',
  POLICY: '#8b5cf6',
  ACTION: '#f59e0b',
  RESOURCE: '#10b981',
  ESCALATION_TARGET: '#ef4444',
}

export default function AttackGraphPanel({ graph }) {
  if (!graph || !graph.nodes?.length) {
    return (
      <div className="text-slate-400 text-sm text-center py-8">
        No attack graph data available.
      </div>
    )
  }

  const { nodes = [], edges = [], attack_paths = [] } = graph

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3 text-center">
        <div className="bg-slate-800 rounded-lg p-3 border border-slate-700">
          <p className="text-2xl font-bold text-blue-400">{nodes.length}</p>
          <p className="text-xs text-slate-400 mt-1">Graph Nodes</p>
        </div>
        <div className="bg-slate-800 rounded-lg p-3 border border-slate-700">
          <p className="text-2xl font-bold text-purple-400">{edges.length}</p>
          <p className="text-xs text-slate-400 mt-1">Edges</p>
        </div>
        <div className="bg-slate-800 rounded-lg p-3 border border-slate-700">
          <p className="text-2xl font-bold text-red-400">{attack_paths.length}</p>
          <p className="text-xs text-slate-400 mt-1">Attack Paths</p>
        </div>
      </div>

      {attack_paths.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-2 uppercase tracking-wide">
            Privilege Escalation Paths
          </h3>
          <div className="space-y-2">
            {attack_paths.map((path) => (
              <div
                key={path.path_id}
                className="bg-red-950 border border-red-800 rounded-lg px-4 py-3"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-red-200">{path.title}</span>
                  <span className="text-xs text-red-400 font-mono">{path.severity}</span>
                </div>
                <p className="text-xs text-red-300">{path.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <h3 className="text-sm font-semibold text-slate-300 mb-2 uppercase tracking-wide">
          Node Legend
        </h3>
        <div className="flex flex-wrap gap-3">
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <div key={type} className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
              <span className="text-xs text-slate-400">{type}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
