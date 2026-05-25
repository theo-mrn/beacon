import { ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react'
import type { RiskLevel } from '../lib/types'

export function RiskBadge({ risk }: { risk: RiskLevel }) {
  if (risk === 'HIGH') return (
    <span className="badge-high">
      <ShieldAlert size={11} />HIGH
    </span>
  )
  if (risk === 'MEDIUM') return (
    <span className="badge-medium">
      <AlertTriangle size={11} />MEDIUM
    </span>
  )
  return (
    <span className="badge-low">
      <ShieldCheck size={11} />LOW
    </span>
  )
}
