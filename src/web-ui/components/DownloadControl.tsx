"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog"
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Download, FileDown, Loader2 } from "lucide-react"

type DownloadFormat = "json" | "csv" | "yaml" | "md" | "docx"

interface DownloadControlProps {
    data: any[]
    defaultFilename: string
    buttonLabel?: string
    columns?: { key: string; label: string; formatter?: (row: any) => string }[]
}

export function DownloadControl({ data, defaultFilename, buttonLabel = "Download", columns = [] }: DownloadControlProps) {
    const [open, setOpen] = useState(false)
    const [format, setFormat] = useState<DownloadFormat>("csv")
    const [filename, setFilename] = useState(defaultFilename)
    const [downloading, setDownloading] = useState(false)

    // Helper: Escape CSV fields
    const escapeCSV = (str: string) => {
        if (!str) return ""
        if (str.includes(",") || str.includes("\"") || str.includes("\n")) {
            return `"${str.replace(/"/g, '""')}"`
        }
        return str
    }

    // Helper: Convert to CSV
    const convertToCSV = () => {
        if (!columns.length) return ""

        const header = columns.map(c => c.label).join(",")
        const rows = data.map(row => {
            return columns.map(col => {
                const val = col.formatter ? col.formatter(row) : (row[col.key] || "")
                return escapeCSV(String(val))
            }).join(",")
        })

        return [header, ...rows].join("\n")
    }

    // Helper: Convert to YAML (Simple impl since we don't have js-yaml)
    const convertToYAML = () => {
        let yaml = ""
        data.forEach(item => {
            yaml += "- \n"
            Object.entries(item).forEach(([key, val]) => {
                // Filter complex non-primitive objects if needed or simply JSON stringify them
                if (typeof val === 'object' && val !== null) {
                    yaml += `  ${key}: ${JSON.stringify(val)}\n`
                } else {
                    yaml += `  ${key}: ${val}\n`
                }
            })
        })
        return yaml
    }

    // Improved YAML converter that respects columns if provided
    const convertToYAMLFormatted = () => {
        if (!columns.length) return convertToYAML()

        let yaml = ""
        data.forEach(row => {
            yaml += "-\n"
            columns.forEach(col => {
                const val = col.formatter ? col.formatter(row) : (row[col.key] || "")
                // Basic YAML escaping
                const strVal = String(val).replace(/:/g, "\\:").replace(/\n/g, "\\n")
                yaml += `  ${col.label}: ${strVal}\n`
            })
        })
        return yaml
    }

    // Helper: Convert to DOCX (simplified HTML-based approach that Word can open)
    const convertToDocx = () => {
        if (!columns.length) {
            // Simple text format
            return data.map(item => JSON.stringify(item, null, 2)).join('\n\n')
        }

        // Create a simple HTML table that Word can import
        let html = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #4472C4; color: white; }
tr:nth-child(even) { background-color: #f2f2f2; }
</style>
</head>
<body>
<h1>${filename}</h1>
<table>
<thead><tr>`

        columns.forEach(col => {
            html += `<th>${col.label}</th>`
        })
        html += `</tr></thead><tbody>`

        data.forEach(row => {
            html += '<tr>'
            columns.forEach(col => {
                const val = col.formatter ? col.formatter(row) : (row[col.key] || "")
                html += `<td>${String(val).replace(/</g, '&lt;').replace(/>/g, '&gt;')}</td>`
            })
            html += '</tr>'
        })

        html += `</tbody></table>
<p><em>Generated on ${new Date().toLocaleString()}</em></p>
</body>
</html>`

        return html
    }

    // Helper: Convert to Markdown Table
    const convertToMarkdown = () => {
        if (!columns.length) return ""

        const headers = columns.map(c => c.label)
        const separator = columns.map(() => "---")

        let md = `| ${headers.join(" | ")} |\n| ${separator.join(" | ")} |\n`

        data.forEach(row => {
            const vals = columns.map(col => {
                const val = col.formatter ? col.formatter(row) : (row[col.key] || "")
                return String(val).replace(/\|/g, "\\|").replace(/\n/g, " ")
            })
            md += `| ${vals.join(" | ")} |\n`
        })

        return md
    }

    const handleDownload = async () => {
        setDownloading(true)
        try {
            let content = ""
            let mimeType = "text/plain"

            switch (format) {
                case "json":
                    content = JSON.stringify(data, null, 2)
                    mimeType = "application/json"
                    break
                case "csv":
                    content = convertToCSV()
                    mimeType = "text/csv"
                    break
                case "yaml":
                    content = convertToYAMLFormatted()
                    mimeType = "text/yaml"
                    break
                case "md":
                    content = convertToMarkdown()
                    mimeType = "text/markdown"
                    break
                case "docx":
                    // For DOCX, we create a simple XML-based document
                    content = convertToDocx()
                    mimeType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    break
            }

            const blob = new Blob([content], { type: mimeType })
            const url = URL.createObjectURL(blob)
            const a = document.createElement("a")
            a.href = url
            // Ensure extension is correct
            const ext = format === "md" ? "md" : format
            const fn = filename.endsWith(`.${ext}`) ? filename : `${filename}.${ext}`

            a.download = fn
            document.body.appendChild(a)
            a.click()
            document.body.removeChild(a)
            URL.revokeObjectURL(url)

            setOpen(false)
        } catch (error) {
            console.error("Download failed:", error)
        } finally {
            setDownloading(false)
        }
    }

    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
                <Button variant="outline" size="sm" className="gap-2">
                    <Download className="h-4 w-4" />
                    {buttonLabel}
                </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[425px]">
                <DialogHeader>
                    <DialogTitle>Download Data</DialogTitle>
                    <DialogDescription>
                        Select format and filename to export this card's data.
                    </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="filename" className="text-right">
                            Filename
                        </Label>
                        <Input
                            id="filename"
                            value={filename}
                            onChange={(e) => setFilename(e.target.value)}
                            className="col-span-3"
                        />
                    </div>
                    <div className="grid grid-cols-4 items-center gap-4">
                        <Label htmlFor="format" className="text-right">
                            Format
                        </Label>
                        <Select value={format} onValueChange={(v: DownloadFormat) => setFormat(v)}>
                            <SelectTrigger className="col-span-3">
                                <SelectValue placeholder="Select format" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="csv">CSV (Excel)</SelectItem>
                                <SelectItem value="json">JSON</SelectItem>
                                <SelectItem value="yaml">YAML</SelectItem>
                                <SelectItem value="md">Markdown</SelectItem>
                                <SelectItem value="docx">DOCX (Word)</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                </div>
                <DialogFooter>
                    <Button type="button" onClick={handleDownload} disabled={downloading}>
                        {downloading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        {downloading ? "Preparing..." : "Download"}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    )
}
