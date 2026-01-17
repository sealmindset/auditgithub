"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import { Settings2, RotateCcw } from "lucide-react"
import { useDashboardLayout, WidgetId } from "@/hooks/useDashboardLayout"
import { cn } from "@/lib/utils"

interface DashboardCustomizerProps {
  layout: ReturnType<typeof useDashboardLayout>
}

export function DashboardCustomizer({ layout }: DashboardCustomizerProps) {
  const [open, setOpen] = useState(false)
  const { configs, isVisible, toggleWidget, resetToDefaults, visibleCount, totalCount } = layout

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="gap-2">
          <Settings2 className="h-4 w-4" />
          <span className="hidden sm:inline">Customize</span>
          <span className="text-xs text-muted-foreground">
            {visibleCount}/{totalCount}
          </span>
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80" align="end">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h4 className="font-medium leading-none">Dashboard Widgets</h4>
              <p className="text-xs text-muted-foreground mt-1">
                Toggle widgets to customize your view
              </p>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={resetToDefaults}
              className="h-8 px-2 text-xs"
            >
              <RotateCcw className="h-3 w-3 mr-1" />
              Reset
            </Button>
          </div>

          <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2">
            {configs.map((config) => (
              <div
                key={config.id}
                className={cn(
                  "flex items-center justify-between py-2 px-2 rounded-md",
                  "hover:bg-muted/50 transition-colors"
                )}
              >
                <div className="flex-1 min-w-0 mr-3">
                  <Label
                    htmlFor={`widget-${config.id}`}
                    className="text-sm font-medium cursor-pointer"
                  >
                    {config.label}
                  </Label>
                  <p className="text-xs text-muted-foreground truncate">
                    {config.description}
                  </p>
                </div>
                <Switch
                  id={`widget-${config.id}`}
                  checked={isVisible(config.id)}
                  onCheckedChange={() => toggleWidget(config.id)}
                />
              </div>
            ))}
          </div>

          <div className="pt-2 border-t text-xs text-muted-foreground">
            Your preferences are saved automatically
          </div>
        </div>
      </PopoverContent>
    </Popover>
  )
}
