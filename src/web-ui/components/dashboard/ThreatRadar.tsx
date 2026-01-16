"use client"

import React, { useEffect, useRef, useCallback, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import Link from "next/link"
import { Eye, Shield, Crosshair } from "lucide-react"

interface ThreatData {
    critical: number
    high: number
    medium: number
    secrets: number
    abandoned: number
    staleContributors: number
    overallScore: number // 0-100
}

interface ThreatRadarProps {
    data: ThreatData
    investigationCount?: number // Number of active investigations (missiles)
    onSegmentClick?: (segment: string) => void
}

// Calculate letter grade from score
function getGrade(score: number): { letter: string; color: string } {
    if (score >= 90) return { letter: "A", color: "#22c55e" }
    if (score >= 80) return { letter: "B", color: "#84cc16" }
    if (score >= 70) return { letter: "C", color: "#eab308" }
    if (score >= 60) return { letter: "D", color: "#f97316" }
    return { letter: "F", color: "#ef4444" }
}

// Threat configuration
const THREATS = [
    { key: "critical", label: "CRIT", fullLabel: "Critical", color: "#ef4444", link: "/findings?severity=critical" },
    { key: "high", label: "HIGH", fullLabel: "High", color: "#f97316", link: "/findings?severity=high" },
    { key: "secrets", label: "SECR", fullLabel: "Secrets", color: "#a855f7", link: "/attack-surface" },
    { key: "staleContributors", label: "STAL", fullLabel: "Stale Users", color: "#3b82f6", link: "/attack-surface" },
    { key: "abandoned", label: "ABAN", fullLabel: "Abandoned", color: "#6b7280", link: "/attack-surface" },
    { key: "medium", label: "MED", fullLabel: "Medium", color: "#eab308", link: "/findings?severity=medium" },
]

// Blip state for animation - exactly 6 blips, one per threat type
interface Blip {
    threatKey: string
    angle: number
    distance: number
    targetDistance: number // Where the blip is moving to
    label: string
    color: string
    value: number
}

// Missile state for defense mode
interface Missile {
    id: number
    fromAngle: number // Launch angle from center
    distance: number // Current distance from center (0 to 1)
    targetBlipKey: string // Which threat it's targeting
    color: string
    active: boolean
}

// Explosion state
interface Explosion {
    x: number
    y: number
    radius: number
    maxRadius: number
    alpha: number
    color: string
}

// Attack missile (from triangles to center)
interface AttackMissile {
    id: number
    fromBlipKey: string
    angle: number
    distance: number // 1 = at triangle, 0 = at center
    color: string
    active: boolean
}

// Center impact effect
interface CenterImpact {
    alpha: number
    flickerPhase: number
    recovering: boolean
    recoveryProgress: number
    color: string
}

type ViewMode = "radar" | "defense" | "attack"

export function ThreatRadar({ data, investigationCount = 0, onSegmentClick }: ThreatRadarProps) {
    const canvasRef = useRef<HTMLCanvasElement>(null)
    const animationRef = useRef<number>()
    const sweepAngleRef = useRef(0)
    const blipsRef = useRef<Blip[]>([])
    const missilesRef = useRef<Missile[]>([])
    const attackMissilesRef = useRef<AttackMissile[]>([])
    const explosionsRef = useRef<Explosion[]>([])
    const centerImpactRef = useRef<CenterImpact>({ alpha: 1, flickerPhase: 0, recovering: false, recoveryProgress: 1, color: "" })
    const missileIdRef = useRef(0)
    const initializedRef = useRef(false)
    const lastMissileLaunchRef = useRef(0)
    const lastAttackMissileLaunchRef = useRef<Record<string, number>>({})

    // View mode state
    const [viewMode, setViewMode] = useState<ViewMode>("radar")

    // Initialize exactly 6 blips - one per threat type
    const initializeBlips = useCallback(() => {
        // Only initialize once, or if we have no blips
        if (initializedRef.current && blipsRef.current.length === 6) {
            // Update values but keep positions
            blipsRef.current.forEach((blip) => {
                const threat = THREATS.find(t => t.key === blip.threatKey)
                if (threat) {
                    const value = data[threat.key as keyof ThreatData] as number
                    blip.value = value
                    blip.label = `${threat.label}-${value}`
                }
            })
            return
        }

        const newBlips: Blip[] = []

        // Distribute 6 blips evenly around the radar - coming from all directions
        THREATS.forEach((threat, index) => {
            const value = data[threat.key as keyof ThreatData] as number
            // Space blips evenly around the circle (60 degrees apart)
            // Start at different positions so they're well spread out
            const baseAngle = (index / 6) * Math.PI * 2
            // Small random offset to avoid perfect symmetry, but keep them spread
            const angle = baseAngle + (Math.random() - 0.5) * 0.3

            newBlips.push({
                threatKey: threat.key,
                angle: angle,
                distance: 0.5 + Math.random() * 0.4, // Random distance (0.5 to 0.9 of radius)
                targetDistance: 0, // Target is always center
                label: `${threat.label}-${value}`,
                color: threat.color,
                value: value,
            })
        })

        blipsRef.current = newBlips
        initializedRef.current = true
    }, [data])

    // Initialize blips when data changes
    useEffect(() => {
        initializeBlips()
    }, [data, initializeBlips])

    const draw = useCallback(() => {
        const canvas = canvasRef.current
        if (!canvas) return

        const ctx = canvas.getContext("2d")
        if (!ctx) return

        const dpr = window.devicePixelRatio || 1
        const rect = canvas.getBoundingClientRect()

        canvas.width = rect.width * dpr
        canvas.height = rect.height * dpr
        ctx.scale(dpr, dpr)

        const centerX = rect.width / 2
        const centerY = rect.height / 2
        const maxRadius = Math.min(centerX, centerY) - 15

        // Clear canvas with dark background
        const bgColors: Record<ViewMode, string> = {
            radar: "#0a0f14",
            defense: "#0a0a12",
            attack: "#140a0a"
        }
        ctx.fillStyle = bgColors[viewMode]
        ctx.fillRect(0, 0, rect.width, rect.height)

        // Draw radar grid (concentric circles)
        const rings = 5
        const gridColors: Record<ViewMode, string> = {
            radar: "rgba(34, 197, 94, 0.12)",
            defense: "rgba(59, 130, 246, 0.12)",
            attack: "rgba(239, 68, 68, 0.12)"
        }
        const gridColorsFaint: Record<ViewMode, string> = {
            radar: "rgba(34, 197, 94, 0.08)",
            defense: "rgba(59, 130, 246, 0.08)",
            attack: "rgba(239, 68, 68, 0.08)"
        }
        const gridColor = gridColors[viewMode]
        const gridColorFaint = gridColorsFaint[viewMode]

        for (let i = 1; i <= rings; i++) {
            const radius = (maxRadius / rings) * i
            ctx.beginPath()
            ctx.arc(centerX, centerY, radius, 0, Math.PI * 2)
            ctx.strokeStyle = gridColor
            ctx.lineWidth = 1
            ctx.stroke()
        }

        // Draw radial lines (12 lines like a clock)
        for (let i = 0; i < 12; i++) {
            const angle = (i / 12) * Math.PI * 2
            ctx.beginPath()
            ctx.moveTo(centerX, centerY)
            ctx.lineTo(
                centerX + Math.cos(angle) * maxRadius,
                centerY + Math.sin(angle) * maxRadius
            )
            ctx.strokeStyle = gridColorFaint
            ctx.lineWidth = 1
            ctx.stroke()
        }

        // Draw sweep line (rotating radar beam)
        sweepAngleRef.current += 0.012
        const sweepAngle = sweepAngleRef.current % (Math.PI * 2)

        // Sweep trail gradient (wider, more visible)
        const trailLength = 0.6 // radians
        const sweepColors: Record<ViewMode, number[]> = {
            radar: [34, 197, 94],
            defense: [59, 130, 246],
            attack: [239, 68, 68]
        }
        const sweepColor = sweepColors[viewMode]
        for (let i = 0; i < 30; i++) {
            const trailAngle = sweepAngle - (i / 30) * trailLength
            const alpha = (1 - i / 30) * 0.25
            ctx.beginPath()
            ctx.moveTo(centerX, centerY)
            ctx.lineTo(
                centerX + Math.cos(trailAngle) * maxRadius,
                centerY + Math.sin(trailAngle) * maxRadius
            )
            ctx.strokeStyle = `rgba(${sweepColor[0]}, ${sweepColor[1]}, ${sweepColor[2]}, ${alpha})`
            ctx.lineWidth = 1.5
            ctx.stroke()
        }

        // Main sweep line
        ctx.beginPath()
        ctx.moveTo(centerX, centerY)
        ctx.lineTo(
            centerX + Math.cos(sweepAngle) * maxRadius,
            centerY + Math.sin(sweepAngle) * maxRadius
        )
        ctx.strokeStyle = `rgba(${sweepColor[0]}, ${sweepColor[1]}, ${sweepColor[2]}, 0.7)`
        ctx.lineWidth = 2
        ctx.stroke()

        // Center circle radius as fraction of maxRadius (30px center circle)
        const centerCircleRadius = 30 / maxRadius

        // === DEFENSE MODE: Launch missiles ===
        if (viewMode === "defense" && investigationCount > 0) {
            const now = Date.now()
            const launchInterval = 2000 // Launch a missile every 2 seconds

            // Maintain missile count based on investigations
            const activeMissiles = missilesRef.current.filter(m => m.active).length
            const maxMissiles = Math.min(investigationCount, 6) // Cap at 6 missiles

            if (activeMissiles < maxMissiles && now - lastMissileLaunchRef.current > launchInterval) {
                // Find a threat to target (prioritize by severity)
                const activeBlips = blipsRef.current.filter(b => b.value > 0 && b.distance > 0.2)
                if (activeBlips.length > 0) {
                    // Prioritize critical, high, then others
                    const sortedBlips = [...activeBlips].sort((a, b) => {
                        const priority: Record<string, number> = { critical: 0, high: 1, secrets: 2, medium: 3, staleContributors: 4, abandoned: 5 }
                        return (priority[a.threatKey] ?? 99) - (priority[b.threatKey] ?? 99)
                    })
                    const target = sortedBlips[0]

                    missilesRef.current.push({
                        id: missileIdRef.current++,
                        fromAngle: target.angle + (Math.random() - 0.5) * 0.3,
                        distance: 0.15, // Start from near center
                        targetBlipKey: target.threatKey,
                        color: "#22d3ee", // Cyan missile
                        active: true
                    })
                    lastMissileLaunchRef.current = now
                }
            }
        }

        // === Update and draw missiles ===
        missilesRef.current = missilesRef.current.filter(missile => {
            if (!missile.active) return false

            // Find target blip
            const targetBlip = blipsRef.current.find(b => b.threatKey === missile.targetBlipKey)
            if (!targetBlip) {
                missile.active = false
                return false
            }

            // Move missile outward (faster than threats)
            missile.distance += 0.015 // 5x faster than threats

            // Adjust angle toward target
            const angleDiff = targetBlip.angle - missile.fromAngle
            missile.fromAngle += angleDiff * 0.05

            // Check collision with target
            const missileX = centerX + Math.cos(missile.fromAngle) * (missile.distance * maxRadius)
            const missileY = centerY + Math.sin(missile.fromAngle) * (missile.distance * maxRadius)
            const blipX = centerX + Math.cos(targetBlip.angle) * (targetBlip.distance * maxRadius)
            const blipY = centerY + Math.sin(targetBlip.angle) * (targetBlip.distance * maxRadius)

            const dx = missileX - blipX
            const dy = missileY - blipY
            const distToTarget = Math.sqrt(dx * dx + dy * dy)

            if (distToTarget < 15 || missile.distance >= targetBlip.distance) {
                // HIT! Create explosion
                explosionsRef.current.push({
                    x: blipX,
                    y: blipY,
                    radius: 0,
                    maxRadius: 25,
                    alpha: 1,
                    color: targetBlip.color
                })

                // Reset the threat to outer edge
                targetBlip.distance = 0.85 + Math.random() * 0.1
                targetBlip.angle = Math.random() * Math.PI * 2

                missile.active = false
                return false
            }

            // Check if missile went past edge
            if (missile.distance > 1) {
                missile.active = false
                return false
            }

            // Draw missile (dash shape)
            const missileLength = 12
            const missileAngle = missile.fromAngle

            ctx.beginPath()
            ctx.moveTo(
                missileX - Math.cos(missileAngle) * missileLength / 2,
                missileY - Math.sin(missileAngle) * missileLength / 2
            )
            ctx.lineTo(
                missileX + Math.cos(missileAngle) * missileLength / 2,
                missileY + Math.sin(missileAngle) * missileLength / 2
            )
            ctx.strokeStyle = missile.color
            ctx.lineWidth = 3
            ctx.lineCap = "round"
            ctx.stroke()

            // Missile trail
            ctx.beginPath()
            ctx.moveTo(
                missileX - Math.cos(missileAngle) * missileLength,
                missileY - Math.sin(missileAngle) * missileLength
            )
            ctx.lineTo(
                missileX - Math.cos(missileAngle) * missileLength * 2,
                missileY - Math.sin(missileAngle) * missileLength * 2
            )
            ctx.strokeStyle = "rgba(34, 211, 238, 0.3)"
            ctx.lineWidth = 2
            ctx.stroke()

            return true
        })

        // === ATTACK MODE: Triangles shoot at center ===
        if (viewMode === "attack") {
            const now = Date.now()

            // Each blip with value > 0 can launch missiles
            blipsRef.current.forEach((blip) => {
                if (blip.value === 0) return

                const lastLaunch = lastAttackMissileLaunchRef.current[blip.threatKey] || 0
                // Launch interval based on severity (critical fires faster)
                const intervalMap: Record<string, number> = {
                    critical: 3000,
                    high: 4000,
                    secrets: 5000,
                    medium: 6000,
                    staleContributors: 7000,
                    abandoned: 8000
                }
                const launchInterval = intervalMap[blip.threatKey] || 5000

                if (now - lastLaunch > launchInterval) {
                    attackMissilesRef.current.push({
                        id: missileIdRef.current++,
                        fromBlipKey: blip.threatKey,
                        angle: blip.angle,
                        distance: blip.distance, // Start at blip position
                        color: blip.color,
                        active: true
                    })
                    lastAttackMissileLaunchRef.current[blip.threatKey] = now
                }
            })
        }

        // === Update and draw attack missiles ===
        attackMissilesRef.current = attackMissilesRef.current.filter(missile => {
            if (!missile.active) return false

            // Move missile toward center (faster than defense missiles)
            missile.distance -= 0.02

            // Check if hit center
            if (missile.distance <= centerCircleRadius + 0.05) {
                // HIT CENTER! Create impact explosion
                const impactX = centerX + Math.cos(missile.angle) * 30
                const impactY = centerY + Math.sin(missile.angle) * 30

                explosionsRef.current.push({
                    x: impactX,
                    y: impactY,
                    radius: 0,
                    maxRadius: 15,
                    alpha: 1,
                    color: missile.color
                })

                // Trigger center impact effect
                centerImpactRef.current = {
                    alpha: 0.3, // Fade to 30%
                    flickerPhase: 0,
                    recovering: true,
                    recoveryProgress: 0,
                    color: missile.color
                }

                missile.active = false
                return false
            }

            // Draw attack missile (red/orange dash pointing at center)
            const missileX = centerX + Math.cos(missile.angle) * (missile.distance * maxRadius)
            const missileY = centerY + Math.sin(missile.angle) * (missile.distance * maxRadius)
            const missileLength = 10
            const missileAngle = missile.angle + Math.PI // Point toward center

            ctx.beginPath()
            ctx.moveTo(
                missileX - Math.cos(missileAngle) * missileLength / 2,
                missileY - Math.sin(missileAngle) * missileLength / 2
            )
            ctx.lineTo(
                missileX + Math.cos(missileAngle) * missileLength / 2,
                missileY + Math.sin(missileAngle) * missileLength / 2
            )
            ctx.strokeStyle = missile.color
            ctx.lineWidth = 3
            ctx.lineCap = "round"
            ctx.stroke()

            // Trail
            ctx.beginPath()
            ctx.moveTo(
                missileX + Math.cos(missileAngle) * missileLength,
                missileY + Math.sin(missileAngle) * missileLength
            )
            ctx.lineTo(
                missileX + Math.cos(missileAngle) * missileLength * 2,
                missileY + Math.sin(missileAngle) * missileLength * 2
            )
            ctx.strokeStyle = `${missile.color}50`
            ctx.lineWidth = 2
            ctx.stroke()

            return true
        })

        // === Update center impact recovery ===
        if (centerImpactRef.current.recovering) {
            const grade = getGrade(data.overallScore)
            // Recovery speed based on grade (A recovers fast, F recovers slow)
            const recoverySpeedMap: Record<string, number> = {
                "A": 0.03,
                "B": 0.02,
                "C": 0.015,
                "D": 0.01,
                "F": 0.005
            }
            const recoverySpeed = recoverySpeedMap[grade.letter] || 0.01

            // Flicker effect during recovery
            centerImpactRef.current.flickerPhase += 0.3
            centerImpactRef.current.recoveryProgress += recoverySpeed

            if (centerImpactRef.current.recoveryProgress >= 1) {
                centerImpactRef.current.recovering = false
                centerImpactRef.current.alpha = 1
                centerImpactRef.current.recoveryProgress = 1
            } else {
                // Flickering alpha during recovery
                const baseAlpha = 0.3 + (centerImpactRef.current.recoveryProgress * 0.7)
                const flicker = Math.sin(centerImpactRef.current.flickerPhase) * 0.15
                centerImpactRef.current.alpha = Math.max(0.2, Math.min(1, baseAlpha + flicker))
            }
        }

        // === Update and draw explosions ===
        explosionsRef.current = explosionsRef.current.filter(explosion => {
            explosion.radius += 2
            explosion.alpha -= 0.05

            if (explosion.alpha <= 0) return false

            // Draw explosion ring
            ctx.beginPath()
            ctx.arc(explosion.x, explosion.y, explosion.radius, 0, Math.PI * 2)
            ctx.strokeStyle = `${explosion.color}${Math.floor(explosion.alpha * 255).toString(16).padStart(2, '0')}`
            ctx.lineWidth = 3
            ctx.stroke()

            // Inner flash
            if (explosion.radius < 15) {
                ctx.beginPath()
                ctx.arc(explosion.x, explosion.y, explosion.radius * 0.5, 0, Math.PI * 2)
                ctx.fillStyle = `rgba(255, 255, 255, ${explosion.alpha * 0.5})`
                ctx.fill()
            }

            return true
        })

        // Update and draw blips
        blipsRef.current.forEach((blip) => {
            // Normalize blip angle to 0-2π
            let blipAngle = blip.angle % (Math.PI * 2)
            if (blipAngle < 0) blipAngle += Math.PI * 2

            // Check if sweep just passed over this blip (within a small arc)
            const sweepTolerance = 0.15 // radians - how close sweep needs to be
            let angleDiff = sweepAngle - blipAngle
            // Normalize angle difference
            while (angleDiff > Math.PI) angleDiff -= Math.PI * 2
            while (angleDiff < -Math.PI) angleDiff += Math.PI * 2

            // If sweep just passed (within tolerance and sweep is ahead)
            if (angleDiff > 0 && angleDiff < sweepTolerance) {
                // Move very slowly toward center - never backwards
                const moveSpeed = 0.003 // Very slow movement toward center
                blip.distance -= moveSpeed

                // Check if reached center circle (touched the grade)
                if (blip.distance <= centerCircleRadius + 0.08) {
                    // Reset to outer position - find angle that's far from other blips
                    blip.distance = 0.8 + Math.random() * 0.15 // Reset to 0.8-0.95

                    // Find the largest gap between existing blips and place there
                    const otherAngles = blipsRef.current
                        .filter(b => b.threatKey !== blip.threatKey)
                        .map(b => b.angle % (Math.PI * 2))
                        .sort((a, b) => a - b)

                    if (otherAngles.length > 0) {
                        // Find largest gap
                        let maxGap = 0
                        let gapStart = 0
                        for (let i = 0; i < otherAngles.length; i++) {
                            const next = (i + 1) % otherAngles.length
                            let gap = otherAngles[next] - otherAngles[i]
                            if (next === 0) gap = (Math.PI * 2 - otherAngles[i]) + otherAngles[0]
                            if (gap > maxGap) {
                                maxGap = gap
                                gapStart = otherAngles[i]
                            }
                        }
                        // Place in middle of largest gap with small random offset
                        blip.angle = gapStart + maxGap / 2 + (Math.random() - 0.5) * 0.3
                    } else {
                        blip.angle = Math.random() * Math.PI * 2
                    }
                }
            }

            const blipX = centerX + Math.cos(blip.angle) * (blip.distance * maxRadius)
            const blipY = centerY + Math.sin(blip.angle) * (blip.distance * maxRadius)

            // Only draw if value > 0
            if (blip.value === 0) return

            // Draw triangle pointing toward center
            const triangleSize = 8
            const pointAngle = blip.angle + Math.PI // Point toward center

            ctx.beginPath()
            ctx.moveTo(
                blipX + Math.cos(pointAngle) * triangleSize * 1.4,
                blipY + Math.sin(pointAngle) * triangleSize * 1.4
            )
            ctx.lineTo(
                blipX + Math.cos(pointAngle + 2.4) * triangleSize,
                blipY + Math.sin(pointAngle + 2.4) * triangleSize
            )
            ctx.lineTo(
                blipX + Math.cos(pointAngle - 2.4) * triangleSize,
                blipY + Math.sin(pointAngle - 2.4) * triangleSize
            )
            ctx.closePath()
            ctx.fillStyle = blip.color
            ctx.fill()

            // Draw label below blip
            const labelOffsetX = 0
            const labelOffsetY = 16

            ctx.font = "bold 9px monospace"
            const textWidth = ctx.measureText(blip.label).width

            // Label background
            ctx.fillStyle = "rgba(10, 15, 20, 0.9)"
            ctx.fillRect(
                blipX + labelOffsetX - textWidth / 2 - 3,
                blipY + labelOffsetY - 6,
                textWidth + 6,
                12
            )

            // Label text
            ctx.fillStyle = blip.color
            ctx.textAlign = "center"
            ctx.textBaseline = "middle"
            ctx.fillText(blip.label, blipX + labelOffsetX, blipY + labelOffsetY)
        })

        // Draw center circle with grade
        const grade = getGrade(data.overallScore)

        // Get alpha for center circle (affected by impacts in attack mode)
        const centerAlpha = viewMode === "attack" ? centerImpactRef.current.alpha : 1

        // Center glow - color based on mode
        const glowColors: Record<ViewMode, string> = {
            radar: grade.color,
            defense: "#3b82f6",
            attack: "#ef4444"
        }
        const glowColor = glowColors[viewMode]
        const centerGlow = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, 45)
        centerGlow.addColorStop(0, `${glowColor}${Math.floor(centerAlpha * 21).toString(16).padStart(2, '0')}`)
        centerGlow.addColorStop(1, "transparent")
        ctx.beginPath()
        ctx.arc(centerX, centerY, 45, 0, Math.PI * 2)
        ctx.fillStyle = centerGlow
        ctx.fill()

        // Impact damage glow (red pulse when recovering)
        if (viewMode === "attack" && centerImpactRef.current.recovering) {
            const damageGlow = ctx.createRadialGradient(centerX, centerY, 25, centerX, centerY, 50)
            const damageAlpha = (1 - centerImpactRef.current.recoveryProgress) * 0.5
            damageGlow.addColorStop(0, `${centerImpactRef.current.color}${Math.floor(damageAlpha * 255).toString(16).padStart(2, '0')}`)
            damageGlow.addColorStop(1, "transparent")
            ctx.beginPath()
            ctx.arc(centerX, centerY, 50, 0, Math.PI * 2)
            ctx.fillStyle = damageGlow
            ctx.fill()
        }

        // Center circle background
        const bgColorsCenter: Record<ViewMode, string> = {
            radar: "#0a0f14",
            defense: "#0a0a12",
            attack: "#140a0a"
        }
        ctx.beginPath()
        ctx.arc(centerX, centerY, 30, 0, Math.PI * 2)
        ctx.fillStyle = bgColorsCenter[viewMode]
        ctx.fill()

        // Center circle border with alpha
        const strokeColors: Record<ViewMode, string> = {
            radar: grade.color,
            defense: "#3b82f6",
            attack: "#ef4444"
        }
        ctx.globalAlpha = centerAlpha
        ctx.strokeStyle = strokeColors[viewMode]
        ctx.lineWidth = 2
        ctx.stroke()
        ctx.globalAlpha = 1

        if (viewMode === "defense") {
            // Defense mode: Show shield icon representation
            ctx.font = "bold 16px monospace"
            ctx.fillStyle = "#3b82f6"
            ctx.textAlign = "center"
            ctx.textBaseline = "middle"
            ctx.fillText("DEF", centerX, centerY - 2)

            // Active investigations count
            ctx.font = "8px monospace"
            ctx.fillStyle = "#22d3ee"
            ctx.fillText(`${investigationCount} ACTIVE`, centerX, centerY + 12)
        } else if (viewMode === "attack") {
            // Attack mode: Show grade with impact effects
            ctx.globalAlpha = centerAlpha
            ctx.font = "bold 20px monospace"
            ctx.fillStyle = "#ef4444"
            ctx.textAlign = "center"
            ctx.textBaseline = "middle"
            ctx.fillText(grade.letter, centerX, centerY - 2)

            // Score below with damage indicator
            ctx.font = "8px monospace"
            if (centerImpactRef.current.recovering) {
                ctx.fillStyle = centerImpactRef.current.color
                ctx.fillText("IMPACT!", centerX, centerY + 12)
            } else {
                ctx.fillStyle = "rgba(239, 68, 68, 0.7)"
                ctx.fillText(`${data.overallScore}%`, centerX, centerY + 12)
            }
            ctx.globalAlpha = 1
        } else {
            // Radar mode: Grade letter
            ctx.font = "bold 20px monospace"
            ctx.fillStyle = grade.color
            ctx.textAlign = "center"
            ctx.textBaseline = "middle"
            ctx.fillText(grade.letter, centerX, centerY - 2)

            // Score below
            ctx.font = "8px monospace"
            ctx.fillStyle = "rgba(148, 163, 184, 0.7)"
            ctx.fillText(`${data.overallScore}%`, centerX, centerY + 12)
        }

        // Continue animation
        animationRef.current = requestAnimationFrame(draw)
    }, [data, viewMode, investigationCount])

    useEffect(() => {
        draw()
        return () => {
            if (animationRef.current) {
                cancelAnimationFrame(animationRef.current)
            }
        }
    }, [draw])

    // Handle resize
    useEffect(() => {
        const handleResize = () => {
            if (animationRef.current) {
                cancelAnimationFrame(animationRef.current)
            }
            draw()
        }
        window.addEventListener("resize", handleResize)
        return () => window.removeEventListener("resize", handleResize)
    }, [draw])

    // Mode display configuration
    const modeConfig: Record<ViewMode, { bg: string; border: string; text: string; icon: React.ReactNode; title: string; status: string }> = {
        radar: {
            bg: "bg-[#0a0f14]",
            border: "border-green-900/30",
            text: "text-green-500",
            icon: <Eye className="h-5 w-5" />,
            title: "Threat Visibility",
            status: "ACTIVE"
        },
        defense: {
            bg: "bg-[#0a0a12]",
            border: "border-blue-900/30",
            text: "text-blue-500",
            icon: <Shield className="h-5 w-5" />,
            title: "Defense Mode",
            status: "ARMED"
        },
        attack: {
            bg: "bg-[#140a0a]",
            border: "border-red-900/30",
            text: "text-red-500",
            icon: <Crosshair className="h-5 w-5" />,
            title: "Attack Simulation",
            status: "THREAT"
        }
    }

    const currentMode = modeConfig[viewMode]

    return (
        <Card className={cn(
            "h-full transition-colors duration-300",
            currentMode.bg,
            currentMode.border
        )}>
            <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                    <CardTitle className={cn(
                        "text-lg font-semibold flex items-center gap-2 transition-colors duration-300",
                        currentMode.text
                    )}>
                        {currentMode.icon}
                        {currentMode.title}
                    </CardTitle>
                    <div className="flex items-center gap-3">
                        {/* Three-way Mode Toggle */}
                        <div className="flex items-center gap-1 bg-black/30 rounded-lg p-1">
                            <button
                                onClick={() => setViewMode("radar")}
                                className={cn(
                                    "px-2 py-1 text-[9px] font-mono rounded transition-all",
                                    viewMode === "radar"
                                        ? "bg-green-600 text-white"
                                        : "text-muted-foreground hover:text-green-500"
                                )}
                            >
                                RADAR
                            </button>
                            <button
                                onClick={() => setViewMode("defense")}
                                className={cn(
                                    "px-2 py-1 text-[9px] font-mono rounded transition-all",
                                    viewMode === "defense"
                                        ? "bg-blue-600 text-white"
                                        : "text-muted-foreground hover:text-blue-500"
                                )}
                            >
                                DEFENSE
                            </button>
                            <button
                                onClick={() => setViewMode("attack")}
                                className={cn(
                                    "px-2 py-1 text-[9px] font-mono rounded transition-all",
                                    viewMode === "attack"
                                        ? "bg-red-600 text-white"
                                        : "text-muted-foreground hover:text-red-500"
                                )}
                            >
                                ATTACK
                            </button>
                        </div>
                        {/* Status indicator */}
                        <div className={cn(
                            "flex items-center gap-1.5 text-xs font-mono transition-colors duration-300",
                            currentMode.text
                        )}>
                            <span className="relative flex h-2 w-2">
                                <span className={cn(
                                    "relative inline-flex rounded-full h-2 w-2",
                                    viewMode === "radar" ? "bg-green-500" :
                                    viewMode === "defense" ? "bg-blue-500" : "bg-red-500"
                                )}></span>
                            </span>
                            {currentMode.status}
                        </div>
                    </div>
                </div>
            </CardHeader>
            <CardContent className="p-3">
                <div className="flex gap-3">
                    {/* Radar Screen - Larger */}
                    <div className="flex-1">
                        <div className="relative aspect-square max-h-[340px] mx-auto">
                            <canvas
                                ref={canvasRef}
                                className="w-full h-full rounded-lg"
                                style={{ width: "100%", height: "100%" }}
                            />
                        </div>
                    </div>

                    {/* Legend - Stacked on right */}
                    <div className="flex flex-col justify-end gap-1 w-24 pb-2">
                        {THREATS.map((threat) => {
                            const value = data[threat.key as keyof ThreatData] as number
                            return (
                                <Link
                                    key={threat.key}
                                    href={threat.link}
                                    className={cn(
                                        "flex items-center gap-1.5 px-2 py-1.5 rounded transition-all font-mono",
                                        "hover:bg-green-500/10 cursor-pointer border border-transparent hover:border-green-500/30",
                                        value > 0 ? "opacity-100" : "opacity-30"
                                    )}
                                >
                                    <div
                                        className="w-0 h-0 border-l-[4px] border-l-transparent border-r-[4px] border-r-transparent border-b-[6px] shrink-0"
                                        style={{ borderBottomColor: threat.color }}
                                    />
                                    <div className="min-w-0 flex-1">
                                        <div className="text-[9px] text-muted-foreground truncate">{threat.fullLabel}</div>
                                        <div className="text-xs font-bold" style={{ color: threat.color }}>{value.toLocaleString()}</div>
                                    </div>
                                </Link>
                            )
                        })}
                    </div>
                </div>
            </CardContent>
        </Card>
    )
}
