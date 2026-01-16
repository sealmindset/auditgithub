"use client"

import { useEffect, useRef, useState } from "react"
import { cn } from "@/lib/utils"

interface AnimatedCounterProps {
    value: number
    duration?: number
    className?: string
    prefix?: string
    suffix?: string
    decimals?: number
}

export function AnimatedCounter({
    value,
    duration = 2000,
    className,
    prefix = "",
    suffix = "",
    decimals = 0
}: AnimatedCounterProps) {
    const [displayValue, setDisplayValue] = useState(0)
    const startTimeRef = useRef<number | null>(null)
    const startValueRef = useRef(0)
    const frameRef = useRef<number>()

    useEffect(() => {
        startValueRef.current = displayValue
        startTimeRef.current = null

        const animate = (timestamp: number) => {
            if (!startTimeRef.current) {
                startTimeRef.current = timestamp
            }

            const progress = Math.min((timestamp - startTimeRef.current) / duration, 1)

            // Easing function for smooth deceleration
            const easeOutQuart = 1 - Math.pow(1 - progress, 4)

            const currentValue = startValueRef.current + (value - startValueRef.current) * easeOutQuart
            setDisplayValue(currentValue)

            if (progress < 1) {
                frameRef.current = requestAnimationFrame(animate)
            }
        }

        frameRef.current = requestAnimationFrame(animate)

        return () => {
            if (frameRef.current) {
                cancelAnimationFrame(frameRef.current)
            }
        }
    }, [value, duration])

    const formattedValue = decimals > 0
        ? displayValue.toFixed(decimals)
        : Math.round(displayValue).toLocaleString()

    return (
        <span className={cn("tabular-nums", className)}>
            {prefix}{formattedValue}{suffix}
        </span>
    )
}
