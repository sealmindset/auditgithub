# Threat Radar Component - LLM Recreation Prompt

## Overview

Create an airport-style radar visualization component for a security dashboard that displays threat categories as triangular blips approaching a central security grade. The component features **three distinct view modes**: Radar (monitoring), Defense (countermeasures), and Attack (threat simulation). The visualization evokes the aesthetic of an air traffic control tower screen, conveying real-time threat visibility and active security response.

## Technology Stack

- **Framework**: Next.js 14+ with React
- **Rendering**: HTML5 Canvas API with `requestAnimationFrame` for smooth 60fps animation
- **Styling**: Tailwind CSS with shadcn/ui Card components
- **Language**: TypeScript

## View Modes

The component supports three distinct visualization modes, selectable via a segmented button control:

### 1. Radar Mode (Default)
- **Theme**: Green (`#22c55e`)
- **Purpose**: Standard threat monitoring view
- **Behavior**: Triangles slowly approach center, reset when touching grade circle
- **Icon**: Eye
- **Status**: "ACTIVE"

### 2. Defense Mode
- **Theme**: Blue (`#3b82f6`)
- **Purpose**: Show active countermeasures (investigations)
- **Behavior**: Missiles launch from center to intercept threats
- **Icon**: Shield
- **Status**: "ARMED"

### 3. Attack Mode
- **Theme**: Red (`#ef4444`)
- **Purpose**: Threat simulation - visualize attack impact
- **Behavior**: Triangles fire missiles at the grade circle, causing impact effects
- **Icon**: Crosshair
- **Status**: "THREAT"

## Visual Design Specifications

### Color Palette by Mode

| Element | Radar Mode | Defense Mode | Attack Mode |
|---------|------------|--------------|-------------|
| Background | `#0a0f14` | `#0a0a12` | `#140a0a` |
| Grid lines | `rgba(34, 197, 94, 0.12)` | `rgba(59, 130, 246, 0.12)` | `rgba(239, 68, 68, 0.12)` |
| Radial lines | `rgba(34, 197, 94, 0.08)` | `rgba(59, 130, 246, 0.08)` | `rgba(239, 68, 68, 0.08)` |
| Sweep beam | Green | Blue | Red |
| Border | `border-green-900/30` | `border-blue-900/30` | `border-red-900/30` |

### Grade Colors (All Modes)

| Grade | Score Range | Color | Hex Code |
|-------|-------------|-------|----------|
| A | 90-100 | Green | `#22c55e` |
| B | 80-89 | Lime | `#84cc16` |
| C | 70-79 | Yellow | `#eab308` |
| D | 60-69 | Orange | `#f97316` |
| F | 0-59 | Red | `#ef4444` |

### Threat Category Colors

| Category | Label | Color | Hex Code | Fire Rate (Attack Mode) |
|----------|-------|-------|----------|------------------------|
| Critical | CRIT | Red | `#ef4444` | 3000ms |
| High | HIGH | Orange | `#f97316` | 4000ms |
| Secrets | SECR | Purple | `#a855f7` | 5000ms |
| Medium | MED | Yellow | `#eab308` | 6000ms |
| Stale Users | STAL | Blue | `#3b82f6` | 7000ms |
| Abandoned | ABAN | Gray | `#6b7280` | 8000ms |

## Component Structure

### Layout

```
+------------------------------------------------------------+
| [Icon] Title            [RADAR|DEFENSE|ATTACK] [*] STATUS  |
+------------------------------------------------------------+
|                                                    |        |
|                                                    | CRIT   |
|              [RADAR CANVAS]                        | HIGH   |
|              max-h: 340px                          | SECR   |
|              aspect-ratio: 1:1                     | STAL   |
|                                                    | ABAN   |
|                                                    | MED    |
+------------------------------------------------------------+
```

### Mode Toggle Button
```tsx
<div className="flex items-center gap-1 bg-black/30 rounded-lg p-1">
    <button className={cn(
        "px-2 py-1 text-[9px] font-mono rounded transition-all",
        viewMode === "radar" ? "bg-green-600 text-white" : "text-muted-foreground hover:text-green-500"
    )}>RADAR</button>
    <button className={cn(
        "px-2 py-1 text-[9px] font-mono rounded transition-all",
        viewMode === "defense" ? "bg-blue-600 text-white" : "text-muted-foreground hover:text-blue-500"
    )}>DEFENSE</button>
    <button className={cn(
        "px-2 py-1 text-[9px] font-mono rounded transition-all",
        viewMode === "attack" ? "bg-red-600 text-white" : "text-muted-foreground hover:text-red-500"
    )}>ATTACK</button>
</div>
```

## Canvas Rendering Details

### Grid System

1. **Concentric Circles (5 rings)**
   - Evenly spaced from center to edge
   - Stroke color varies by mode
   - Line width: 1px

2. **Radial Lines (12 lines)**
   - Like clock hour markers, every 30 degrees
   - Stroke color varies by mode (faint)
   - Line width: 1px

### Sweep Beam Animation

1. **Rotation**
   - Speed: `0.012` radians per frame (~0.7 degrees/frame)
   - Direction: Clockwise
   - Continuous rotation using `requestAnimationFrame`

2. **Trail Effect**
   - Length: `0.6` radians (~34 degrees)
   - 30 gradient steps fading from `alpha=0.25` to `alpha=0`
   - Line width: 1.5px
   - Color varies by mode

3. **Main Beam**
   - Alpha: 0.7
   - Line width: 2px

### Blip (Triangle) System

#### Initialization
- Exactly **6 blips** - one per threat category
- Initial positions distributed evenly around the radar (60 degrees apart)
- Small random angular offset (±0.15 radians) to avoid perfect symmetry
- Starting distance: random between 0.5 and 0.9 of radius

#### Triangle Shape
- Size: 8px base dimension
- Points toward center (in direction of movement)
- Filled with threat category color
- Shape calculation:
  ```
  Point angle = blip.angle + PI (toward center)
  Tip: pointAngle * 1.4 * size
  Left: pointAngle + 2.4 radians * size
  Right: pointAngle - 2.4 radians * size
  ```

#### Movement Behavior (All Modes)

**Critical Rule: Triangles ONLY move when the radar sweep passes over them**

1. **Sweep Detection**
   - Tolerance: 0.15 radians
   - Only move when sweep angle is just ahead of blip angle
   - Check: `angleDiff > 0 && angleDiff < sweepTolerance`

2. **Movement Speed**
   - Very slow: `0.003` per sweep pass
   - Always toward center (never backwards)
   - `blip.distance -= moveSpeed`

3. **Reset on Center Touch**
   - Trigger: when distance reaches center circle radius + 0.08
   - Reset distance: random 0.8-0.95 of radius
   - New angle: placed in largest gap between other blips

#### Gap-Finding Algorithm for Reset
```typescript
// Find angles of other 5 blips, sorted
const otherAngles = blips
    .filter(b => b.key !== currentBlip.key)
    .map(b => b.angle % (2*PI))
    .sort()

// Find largest gap
let maxGap = 0, gapStart = 0
for (let i = 0; i < otherAngles.length; i++) {
    const next = (i + 1) % otherAngles.length
    let gap = otherAngles[next] - otherAngles[i]
    if (next === 0) gap = (2*PI - otherAngles[i]) + otherAngles[0]
    if (gap > maxGap) { maxGap = gap; gapStart = otherAngles[i] }
}

// Place in middle of gap
newAngle = gapStart + maxGap/2 + random(-0.15, 0.15)
```

#### Labels
- Position: 16px below triangle center
- Font: `bold 9px monospace`
- Format: `{ABBREV}-{count}` (e.g., "CRIT-176")
- Background: `rgba(10, 15, 20, 0.9)` rounded rectangle
- Text color: matches threat category color

## Defense Mode - Missile System

### Defense Missile Interface
```typescript
interface Missile {
    id: number
    fromAngle: number      // Launch angle from center
    distance: number       // 0 to 1 (center to edge)
    targetBlipKey: string  // Which threat to intercept
    color: string          // Cyan: "#22d3ee"
    active: boolean
}
```

### Missile Launch Logic
- Launches from center toward threats
- Number of active missiles based on `investigationCount` prop
- Launch interval: 2000ms between missiles
- Max simultaneous missiles: `min(investigationCount, 6)`
- Priority targeting: Critical > High > Secrets > Medium > Stale > Abandoned

### Missile Movement
- Speed: `0.015` per frame (5x faster than threats)
- Tracks target with angle adjustment: `missile.fromAngle += angleDiff * 0.05`
- Collision detection: distance < 15px or missile.distance >= target.distance

### On Hit
1. Create explosion at target location
2. Reset target blip to outer edge with new random angle
3. Deactivate missile

### Missile Rendering
```typescript
// Dash shape
ctx.beginPath()
ctx.moveTo(missileX - Math.cos(angle) * 6, missileY - Math.sin(angle) * 6)
ctx.lineTo(missileX + Math.cos(angle) * 6, missileY + Math.sin(angle) * 6)
ctx.strokeStyle = "#22d3ee"
ctx.lineWidth = 3
ctx.lineCap = "round"
ctx.stroke()

// Trail
ctx.strokeStyle = "rgba(34, 211, 238, 0.3)"
ctx.lineWidth = 2
// Draw trail behind missile
```

## Attack Mode - Incoming Fire System

### Attack Missile Interface
```typescript
interface AttackMissile {
    id: number
    fromBlipKey: string  // Which threat fired it
    angle: number        // Direction toward center
    distance: number     // 1 = at triangle, 0 = at center
    color: string        // Matches threat color
    active: boolean
}
```

### Center Impact Interface
```typescript
interface CenterImpact {
    alpha: number           // Current opacity (0.3 to 1)
    flickerPhase: number    // For flicker animation
    recovering: boolean     // Is currently recovering
    recoveryProgress: number // 0 to 1
    color: string           // Color of last impact
}
```

### Attack Launch Logic
- Each threat category fires missiles at different rates (see Threat Category Colors table)
- Critical threats fire fastest (3s), Abandoned slowest (8s)
- Missiles start at the triangle's current position

### Attack Missile Movement
- Speed: `0.02` per frame toward center
- No tracking - fires straight toward center from launch angle

### On Center Hit
1. Create explosion at center circle edge
2. Trigger center impact effect:
   - Alpha drops to 0.3
   - Flickering begins
   - Recovery starts

### Recovery System (Grade-Based)
```typescript
const recoverySpeedMap: Record<string, number> = {
    "A": 0.03,   // Fast recovery
    "B": 0.02,
    "C": 0.015,
    "D": 0.01,
    "F": 0.005   // Very slow recovery
}
```

The worse the grade, the longer it takes to recover from attacks. This creates a visual metaphor: organizations with poor security posture (Grade F) are more vulnerable to sustained attacks.

### Impact Visual Effects
1. **Damage Glow**: Red pulse around center during recovery
2. **Flicker Effect**: `sin(flickerPhase) * 0.15` added to alpha
3. **"IMPACT!" Text**: Replaces score during recovery
4. **Alpha Fade**: All center elements fade based on `centerAlpha`

## Explosion System (Both Modes)

### Explosion Interface
```typescript
interface Explosion {
    x: number
    y: number
    radius: number      // Grows over time
    maxRadius: number   // 25 for defense, 15 for attack
    alpha: number       // Fades over time
    color: string       // Matches source color
}
```

### Explosion Animation
```typescript
explosion.radius += 2
explosion.alpha -= 0.05

// Outer ring
ctx.arc(explosion.x, explosion.y, explosion.radius, 0, Math.PI * 2)
ctx.strokeStyle = `${explosion.color}${alphaHex}`
ctx.lineWidth = 3
ctx.stroke()

// Inner flash (while radius < 15)
ctx.arc(explosion.x, explosion.y, explosion.radius * 0.5, 0, Math.PI * 2)
ctx.fillStyle = `rgba(255, 255, 255, ${explosion.alpha * 0.5})`
ctx.fill()
```

## Center Grade Circle

### Standard Rendering
1. **Glow Effect**
   - Radial gradient from center
   - Color varies by mode
   - Radius: 45px
   - Affected by `centerAlpha` in attack mode

2. **Circle**
   - Radius: 30px
   - Fill: mode background color
   - Stroke: mode accent color, 2px width
   - Affected by `centerAlpha` in attack mode

3. **Content by Mode**:
   - **Radar**: Grade letter + score percentage
   - **Defense**: "DEF" + investigation count
   - **Attack**: Grade letter (with alpha) + "IMPACT!" or score

### Grade Calculation
```typescript
function getGrade(score: number): { letter: string; color: string } {
    if (score >= 90) return { letter: "A", color: "#22c55e" }
    if (score >= 80) return { letter: "B", color: "#84cc16" }
    if (score >= 70) return { letter: "C", color: "#eab308" }
    if (score >= 60) return { letter: "D", color: "#f97316" }
    return { letter: "F", color: "#ef4444" }
}
```

## Data Interface

```typescript
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
    investigationCount?: number  // For defense mode missiles
    onSegmentClick?: (segment: string) => void
}
```

## State Management

```typescript
type ViewMode = "radar" | "defense" | "attack"

// Refs for animation state
const canvasRef = useRef<HTMLCanvasElement>(null)
const animationRef = useRef<number>()
const sweepAngleRef = useRef(0)
const blipsRef = useRef<Blip[]>([])
const missilesRef = useRef<Missile[]>([])           // Defense mode
const attackMissilesRef = useRef<AttackMissile[]>([]) // Attack mode
const explosionsRef = useRef<Explosion[]>([])
const centerImpactRef = useRef<CenterImpact>({...})
const missileIdRef = useRef(0)
const lastMissileLaunchRef = useRef(0)
const lastAttackMissileLaunchRef = useRef<Record<string, number>>({})

// React state
const [viewMode, setViewMode] = useState<ViewMode>("radar")
```

## Animation Loop Architecture

```typescript
const draw = useCallback(() => {
    // 1. Get canvas context and handle DPR
    // 2. Clear and fill background (mode-specific color)
    // 3. Draw grid (mode-specific colors)
    // 4. Draw sweep beam (mode-specific color)
    // 5. If defense mode: launch and update defense missiles
    // 6. If attack mode: launch and update attack missiles
    // 7. Update center impact recovery
    // 8. Update and draw explosions
    // 9. Update blip positions (sweep-triggered)
    // 10. Draw blips and labels
    // 11. Draw center circle with impact effects
    // 12. Request next frame
    animationRef.current = requestAnimationFrame(draw)
}, [data, viewMode, investigationCount])
```

## Legend Panel

### Layout
- Positioned to the right of the radar
- Stacked vertically
- Width: 96px (w-24)
- Aligned to bottom (`justify-end`)

### Legend Items
- Each item is a clickable Link to relevant page
- Contains:
  - Small triangle icon (CSS borders)
  - Label (e.g., "Critical", "High")
  - Count value with thousand separators
- Hover effect: green background tint

## Dependencies

```json
{
    "react": "^18.x",
    "lucide-react": "^0.x (Eye, Shield, Crosshair icons)",
    "@/components/ui/card": "shadcn/ui Card components",
    "@/lib/utils": "cn utility function",
    "next/link": "Next.js routing"
}
```

## Example Usage

```tsx
<ThreatRadar
    data={{
        critical: 176,
        high: 432,
        medium: 891,
        secrets: 23,
        abandoned: 45,
        staleContributors: 12,
        overallScore: 72
    }}
    investigationCount={5}  // Enables defense mode missiles
/>
```

## Key Design Principles

1. **Airport Control Tower Aesthetic**: Professional, technical, surveillance-oriented visualization.

2. **Three Distinct Narratives**:
   - **Radar**: "We see the threats approaching"
   - **Defense**: "We're actively fighting back"
   - **Attack**: "This is what happens without defense"

3. **Grade-Based Resilience**: Attack mode visually demonstrates that organizations with poor grades (F) suffer longer from attacks than those with good grades (A).

4. **Color-Coded Severity**: Immediate visual recognition of threat severity through consistent color coding.

5. **Spatial Distribution**: Triangles always appear from all directions, never bunched together.

6. **Meaningful Animation**: Every animation serves a purpose:
   - Sweep: Shows active scanning
   - Triangle movement: Threats closing in
   - Missiles: Active response or incoming fire
   - Impact effects: Consequence visualization

## Performance Considerations

- Use `requestAnimationFrame` for smooth 60fps animation
- Minimize object creation in the draw loop
- Use refs for mutable animation state to avoid re-renders
- Canvas operations are batched per frame
- Filter out inactive missiles/explosions each frame

## Common Pitfalls to Avoid

1. **Too many triangles**: Always exactly 6, one per category
2. **Continuous movement**: Triangles should ONLY move when sweep passes
3. **Fast movement**: Keep triangle speed very slow (0.003 per pass)
4. **Bunched triangles**: Use gap-finding algorithm on reset
5. **Backward movement**: Triangles only move toward center
6. **Instant recovery**: Attack mode recovery should be grade-dependent
7. **Missing mode transitions**: Ensure smooth color transitions between modes
8. **Forgotten cleanup**: Clear missiles/explosions when switching modes
