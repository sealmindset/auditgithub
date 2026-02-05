"use client"

import { AlertTriangle, Shield } from "lucide-react"

export default function BreakGlassBanner() {
  return (
    <div className="bg-red-600 text-white px-4 py-3 shadow-lg">
      <div className="container mx-auto flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 flex-shrink-0 animate-pulse" />
          <div className="flex flex-col sm:flex-row sm:items-center sm:gap-2">
            <p className="font-bold text-sm sm:text-base">
              BREAK GLASS MODE ACTIVE
            </p>
            <p className="text-xs sm:text-sm opacity-90">
              Emergency access - All actions are being audited and logged
            </p>
          </div>
        </div>
        <Shield className="h-5 w-5 flex-shrink-0 opacity-75" />
      </div>
    </div>
  )
}
