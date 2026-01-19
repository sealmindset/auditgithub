"use client"

import { useState, useEffect, useRef } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Progress } from "@/components/ui/progress"
import {
    Download,
    FileText,
    FileJson,
    FileSpreadsheet,
    FileType,
    Loader2,
    X,
    Shield,
    AlertTriangle,
    AlertCircle,
    CheckCircle,
    Users,
    Code,
    GitBranch,
    Calendar,
    TrendingUp,
    Lock,
    Bug,
    Server,
    Package,
    Workflow,
    Globe,
    ChevronRight,
    Sparkles
} from "lucide-react"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

const API_BASE = "http://localhost:8000"

interface SecurityReportModalProps {
    projectId: string
    projectName: string
    isOpen: boolean
    onClose: () => void
}

interface ReportData {
    report_id: string
    generated_at: string
    project: any
    executive_summary: string
    critical_insights?: Array<{
        type: string  // e.g., "Remote Code Execution", "SQL Injection", "Analyst Highlighted"
        category: string
        title: string
        severity: string
        message: string
        file_path?: string
        line?: number
        finding_id: string
        code_snippet?: string
        manually_included?: boolean  // True if Security Analyst manually included via checkbox
    }>
    architecture: {
        report: string
        diagram_base64: string | null
        insights: string
    }
    project_insights: {
        development_evaluation: string
        contributor_count: number
        contributor_analysis: string
        language_breakdown: Record<string, number>
        additional_context: Record<string, any>
    }
    highlight_reel: Array<{
        category: string
        title: string
        severity: string
        impact: string
        finding_id: string
        analysis: string
        file_path?: string
        line?: number
        code_snippet?: string  // Full unredacted code for security analyst validation
    }>
    findings: {
        secrets: any[]
        sast: any[]
        infrastructure: any[]
        dependencies: any[]
        cicd: any[]
        contributors: any[]
        languages: Record<string, number>
        sbom: any[]
        api_audit: any[]
    }
    risk_score: {
        overall: number
        secrets: number
        sast: number
        infrastructure: number
        dependencies: number
    }
}

export function SecurityReportModal({ projectId, projectName, isOpen, onClose }: SecurityReportModalProps) {
    const [loading, setLoading] = useState(false)
    const [generating, setGenerating] = useState(false)
    const [reportData, setReportData] = useState<ReportData | null>(null)
    const [error, setError] = useState<string | null>(null)
    const [activeSection, setActiveSection] = useState("executive")
    const reportRef = useRef<HTMLDivElement>(null)
    
    // Export filename dialog state
    const [exportDialogOpen, setExportDialogOpen] = useState(false)
    const [exportFormat, setExportFormat] = useState<string>("")
    const [exportFilename, setExportFilename] = useState("")

    useEffect(() => {
        if (isOpen && !reportData) {
            generateReport()
        }
    }, [isOpen])

    const generateReport = async () => {
        setGenerating(true)
        setError(null)

        try {
            const res = await fetch(`${API_BASE}/projects/${projectId}/security-report`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    include_architecture: true,
                    include_diagram: true,
                    highlight_count: 10
                })
            })

            if (!res.ok) {
                const err = await res.json()
                throw new Error(err.detail || "Failed to generate report")
            }

            const data = await res.json()
            setReportData(data)
        } catch (err) {
            setError(err instanceof Error ? err.message : "An unknown error occurred")
        } finally {
            setGenerating(false)
        }
    }

    const getRiskColor = (score: number) => {
        if (score >= 80) return "text-red-500"
        if (score >= 60) return "text-orange-500"
        if (score >= 40) return "text-yellow-500"
        return "text-green-500"
    }

    const getRiskBgColor = (score: number) => {
        if (score >= 80) return "bg-red-500"
        if (score >= 60) return "bg-orange-500"
        if (score >= 40) return "bg-yellow-500"
        return "bg-green-500"
    }

    const getSeverityIcon = (severity: string) => {
        switch (severity.toLowerCase()) {
            case "critical": return <AlertCircle className="h-5 w-5 text-red-500" />
            case "high": return <AlertTriangle className="h-5 w-5 text-orange-500" />
            case "medium": return <AlertTriangle className="h-5 w-5 text-yellow-500" />
            default: return <CheckCircle className="h-5 w-5 text-blue-500" />
        }
    }

    const getCategoryIcon = (category: string) => {
        switch (category.toLowerCase()) {
            case "secrets": return <Lock className="h-4 w-4" />
            case "sast": return <Bug className="h-4 w-4" />
            case "infrastructure": return <Server className="h-4 w-4" />
            case "dependencies": return <Package className="h-4 w-4" />
            case "cicd": return <Workflow className="h-4 w-4" />
            case "api_audit": return <Globe className="h-4 w-4" />
            default: return <Shield className="h-4 w-4" />
        }
    }

    // Severity sort order: critical, high, medium, low, informational
    const severityOrder: Record<string, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        informational: 4
    }

    const sortBySeverity = (items: any[]): any[] => {
        return [...items].sort((a, b) => {
            const aOrder = severityOrder[(a.severity || 'informational').toLowerCase()] ?? 5
            const bOrder = severityOrder[(b.severity || 'informational').toLowerCase()] ?? 5
            return aOrder - bOrder
        })
    }

    // Opens the filename dialog for PDF/DOCX, or exports directly for other formats
    const handleExportClick = (format: string) => {
        if (!reportData) return
        
        const defaultFilename = `security-report-${projectName}-${new Date().toISOString().split('T')[0]}`
        
        // For PDF and DOCX, show filename dialog
        if (format === "pdf" || format === "docx") {
            setExportFormat(format)
            setExportFilename(defaultFilename)
            setExportDialogOpen(true)
        } else {
            // For other formats, export directly with default filename
            exportReport(format, defaultFilename)
        }
    }
    
    // Confirms the export with the user-specified filename
    const confirmExport = async () => {
        if (!reportData || !exportFilename.trim()) return
        
        await exportReport(exportFormat, exportFilename.trim())
        setExportDialogOpen(false)
    }

    const exportReport = async (format: string, filename: string) => {
        if (!reportData) return

        switch (format) {
            case "json":
                downloadFile(JSON.stringify(reportData, null, 2), `${filename}.json`, "application/json")
                break
            case "markdown":
                downloadFile(generateMarkdown(reportData), `${filename}.md`, "text/markdown")
                break
            case "csv":
                downloadFile(generateCSV(reportData), `${filename}.csv`, "text/csv")
                break
            case "pdf":
                await generatePDF(reportData, filename)
                break
            case "docx":
                await generateDOCX(reportData, filename)
                break
        }
    }

    const downloadFile = async (content: string, filename: string, mimeType: string) => {
        const blob = new Blob([content], { type: mimeType })
        
        // Try to use File System Access API for native "Save As" dialog
        if ('showSaveFilePicker' in window) {
            try {
                const extension = filename.split('.').pop() || 'txt'
                const handle = await (window as any).showSaveFilePicker({
                    suggestedName: filename,
                    types: [{
                        description: `${extension.toUpperCase()} File`,
                        accept: { [mimeType]: [`.${extension}`] }
                    }]
                })
                const writable = await handle.createWritable()
                await writable.write(blob)
                await writable.close()
                return
            } catch (err: any) {
                // User cancelled or API not supported, fall back to traditional download
                if (err.name === 'AbortError') return
            }
        }
        
        // Fallback: traditional download
        const url = URL.createObjectURL(blob)
        const a = document.createElement("a")
        a.href = url
        a.download = filename
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
    }

    const generateMarkdown = (data: ReportData): string => {
        let md = `# Security Assessment Report: ${data.project?.name || projectName}\n\n`
        md += `**Generated:** ${new Date(data.generated_at).toLocaleString()}\n\n`
        md += `**Overall Risk Score:** ${data.risk_score?.overall || 'N/A'}/100\n\n`
        md += `---\n\n`

        // Executive Summary
        md += `## Executive Summary\n\n${data.executive_summary || 'No summary available.'}\n\n`

        // Architecture
        if (data.architecture?.report) {
            md += `## System Architecture\n\n${data.architecture.report}\n\n`
            if (data.architecture.insights) {
                md += `### AI Insights\n\n${data.architecture.insights}\n\n`
            }
        }

        // Project Insights
        md += `## Project Insights\n\n`
        if (data.project_insights) {
            md += `### Development Evaluation\n\n${data.project_insights.development_evaluation || 'N/A'}\n\n`
            md += `### Contributors\n\n- **Total Contributors:** ${data.project_insights.contributor_count || 0}\n`
            md += `${data.project_insights.contributor_analysis || ''}\n\n`
            
            if (data.project_insights.language_breakdown) {
                md += `### Languages\n\n`
                Object.entries(data.project_insights.language_breakdown).forEach(([lang, pct]) => {
                    md += `- **${lang}:** ${pct}%\n`
                })
                md += `\n`
            }
        }

        // Highlight Reel
        md += `## Critical Findings Highlight Reel\n\n`
        if (data.highlight_reel && data.highlight_reel.length > 0) {
            data.highlight_reel.forEach((highlight, idx) => {
                md += `### ${idx + 1}. ${highlight.title}\n\n`
                md += `- **Category:** ${highlight.category}\n`
                md += `- **Severity:** ${highlight.severity}\n`
                md += `- **Impact:** ${highlight.impact}\n`
                if (highlight.file_path) md += `- **Location:** ${highlight.file_path}${highlight.line ? `:${highlight.line}` : ''}\n`
                md += `\n${highlight.analysis}\n\n`
            })
        } else {
            md += `No critical findings identified.\n\n`
        }

        // Findings Summary
        md += `## Findings Summary\n\n`
        md += `| Category | Count |\n|----------|-------|\n`
        md += `| Secrets | ${data.findings?.secrets?.length || 0} |\n`
        md += `| SAST | ${data.findings?.sast?.length || 0} |\n`
        md += `| Infrastructure | ${data.findings?.infrastructure?.length || 0} |\n`
        md += `| Dependencies | ${data.findings?.dependencies?.length || 0} |\n`
        md += `| API Audit | ${data.findings?.api_audit?.length || 0} |\n\n`

        return md
    }

    const generateCSV = (data: ReportData): string => {
        const rows: string[][] = []
        rows.push(["Category", "Severity", "Title", "File", "Line", "Description"])

        const addFindings = (findings: any[], category: string) => {
            findings?.forEach(f => {
                rows.push([
                    category,
                    f.severity || "",
                    f.title || f.name || "",
                    f.file_path || f.file || "",
                    f.line?.toString() || "",
                    (f.description || f.message || "").replace(/"/g, '""')
                ])
            })
        }

        addFindings(data.findings?.secrets, "Secrets")
        addFindings(data.findings?.sast, "SAST")
        addFindings(data.findings?.infrastructure, "Infrastructure")
        addFindings(data.findings?.dependencies, "Dependencies")
        addFindings(data.findings?.api_audit, "API Audit")

        return rows.map(row => row.map(cell => `"${cell}"`).join(",")).join("\n")
    }

    const generatePDF = async (data: ReportData, filename: string) => {
        // Dynamic import for PDF generation
        const html2pdf = (await import("html2pdf.js")).default
        
        // Build standalone HTML content for PDF (not from DOM which has scroll issues)
        const htmlContent = buildPDFHtml(data)
        
        // Create an iframe to completely isolate styles from the main page
        const iframe = document.createElement('iframe')
        iframe.style.position = 'absolute'
        iframe.style.left = '-9999px'
        iframe.style.top = '0'
        iframe.style.width = '210mm'
        iframe.style.height = '297mm'
        iframe.style.border = 'none'
        document.body.appendChild(iframe)
        
        // Write content to iframe
        const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document
        if (!iframeDoc) {
            document.body.removeChild(iframe)
            console.error('Could not access iframe document')
            return
        }
        
        iframeDoc.open()
        iframeDoc.write(`<!DOCTYPE html><html><head><style>* { margin: 0; padding: 0; box-sizing: border-box; }</style></head><body>${htmlContent}</body></html>`)
        iframeDoc.close()
        
        // Wait for iframe content to render
        await new Promise(resolve => setTimeout(resolve, 100))
        
        const container = iframeDoc.body
        
        const opt = {
            margin: [10, 10, 10, 10],
            filename: `${filename}.pdf`,
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: { 
                scale: 2, 
                useCORS: true,
                logging: false,
                windowWidth: 794 // A4 width in pixels at 96 DPI
            },
            jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
            pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
        }
        
        try {
            // Try to use File System Access API for native "Save As" dialog
            if ('showSaveFilePicker' in window) {
                try {
                    const handle = await (window as any).showSaveFilePicker({
                        suggestedName: `${filename}.pdf`,
                        types: [{
                            description: 'PDF Document',
                            accept: { 'application/pdf': ['.pdf'] }
                        }]
                    })
                    
                    // Generate PDF as blob
                    const pdfBlob = await html2pdf().set(opt).from(container).outputPdf('blob')
                    
                    const writable = await handle.createWritable()
                    await writable.write(pdfBlob)
                    await writable.close()
                    return
                } catch (err: any) {
                    // User cancelled or API not supported, fall back to traditional download
                    if (err.name === 'AbortError') return
                }
            }
            
            // Fallback: traditional download
            await html2pdf().set(opt).from(container).save()
        } finally {
            // Clean up iframe
            document.body.removeChild(iframe)
        }
    }
    
    const buildPDFHtml = (data: ReportData): string => {
        const escapeHtml = (str: string) => str?.replace(/[&<>"']/g, (m) => 
            ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m] || m)) || ''
        
        const getRiskLabel = (score: number) => {
            if (score >= 80) return { label: 'Critical Risk', color: '#ef4444' }
            if (score >= 60) return { label: 'High Risk', color: '#f97316' }
            if (score >= 40) return { label: 'Medium Risk', color: '#eab308' }
            return { label: 'Low Risk', color: '#22c55e' }
        }
        
        const riskInfo = getRiskLabel(data.risk_score?.overall || 0)
        
        // Use a complete HTML document with reset styles to avoid inheriting problematic CSS
        let html = `
        <style>
            * { all: revert; box-sizing: border-box; }
            .pdf-container * { font-family: Arial, Helvetica, sans-serif !important; }
        </style>
        <div class="pdf-container" style="font-family: Arial, Helvetica, sans-serif; color: #1f2937; line-height: 1.6; padding: 20px; background: white;">
            <!-- Header -->
            <div style="text-align: center; margin-bottom: 30px; border-bottom: 3px solid #3b82f6; padding-bottom: 20px;">
                <h1 style="color: #1e40af; margin: 0 0 10px 0; font-size: 28px;">Security Assessment Report</h1>
                <h2 style="color: #6b7280; margin: 0; font-size: 18px; font-weight: normal;">${escapeHtml(data.project?.name || projectName)}</h2>
                <p style="color: #9ca3af; margin: 10px 0 0 0; font-size: 12px;">Generated: ${new Date(data.generated_at).toLocaleString()}</p>
            </div>
            
            <!-- Risk Score Overview -->
            <div style="background-color: #1e293b; color: #ffffff; padding: 20px; border-radius: 12px; margin-bottom: 25px;">
                <h3 style="margin: 0 0 15px 0; font-size: 16px;">Overall Risk Score</h3>
                <div style="display: flex; align-items: center; gap: 20px;">
                    <div style="font-size: 48px; font-weight: bold; color: ${riskInfo.color};">${data.risk_score?.overall || 0}</div>
                    <div>
                        <div style="background: #475569; border-radius: 8px; height: 12px; width: 200px; overflow: hidden;">
                            <div style="background: ${riskInfo.color}; height: 100%; width: ${data.risk_score?.overall || 0}%;"></div>
                        </div>
                        <p style="margin: 5px 0 0 0; font-size: 12px; color: #94a3b8;">${riskInfo.label}</p>
                    </div>
                </div>
                <div style="display: flex; gap: 30px; margin-top: 20px;">
                    <div><strong>Secrets:</strong> ${data.risk_score?.secrets || 0}</div>
                    <div><strong>SAST:</strong> ${data.risk_score?.sast || 0}</div>
                    <div><strong>Infrastructure:</strong> ${data.risk_score?.infrastructure || 0}</div>
                    <div><strong>Dependencies:</strong> ${data.risk_score?.dependencies || 0}</div>
                </div>
            </div>
            
            <!-- Executive Summary -->
            <div style="margin-bottom: 25px; page-break-inside: avoid;">
                <h2 style="color: #1e40af; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; font-size: 20px;">Executive Summary</h2>
                <div style="background: #f9fafb; padding: 15px; border-radius: 8px; border-left: 4px solid #3b82f6;">
                    ${data.executive_summary?.replace(/\n/g, '<br>') || 'No executive summary available.'}
                </div>
            </div>`
        
        // Architecture Section
        if (data.architecture?.report) {
            html += `
            <div style="margin-bottom: 25px; page-break-inside: avoid;">
                <h2 style="color: #1e40af; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; font-size: 20px;">System Architecture</h2>`
            
            if (data.architecture.diagram_base64) {
                html += `
                <div style="text-align: center; background: white; padding: 15px; border-radius: 8px; margin-bottom: 15px; border: 1px solid #e5e7eb;">
                    <img src="data:image/png;base64,${data.architecture.diagram_base64}" style="max-width: 100%; height: auto;" alt="Architecture Diagram" />
                </div>`
            }
            
            html += `
                <div style="background: #f9fafb; padding: 15px; border-radius: 8px;">
                    ${data.architecture.report.replace(/\n/g, '<br>')}
                </div>
            </div>`
        }
        
        // Critical Findings / Highlight Reel
        if (data.highlight_reel && data.highlight_reel.length > 0) {
            html += `
            <div style="margin-bottom: 25px;">
                <h2 style="color: #1e40af; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; font-size: 20px;">Critical Findings</h2>`
            
            data.highlight_reel.forEach((item, idx) => {
                const severityColors: Record<string, string> = {
                    critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#16a34a'
                }
                const sevColor = severityColors[item.severity?.toLowerCase()] || '#6b7280'
                
                html += `
                <div style="background: #fef2f2; border: 1px solid #fecaca; border-left: 4px solid ${sevColor}; padding: 15px; border-radius: 8px; margin-bottom: 15px; page-break-inside: avoid;">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
                        <h3 style="margin: 0; color: #1f2937; font-size: 16px;">${idx + 1}. ${escapeHtml(item.title)}</h3>
                        <span style="background: ${sevColor}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">${item.severity?.toUpperCase()}</span>
                    </div>
                    <p style="margin: 0 0 8px 0; font-size: 13px;"><strong>Category:</strong> ${escapeHtml(item.category)}</p>
                    ${item.file_path ? `<p style="margin: 0 0 8px 0; font-size: 13px;"><strong>Location:</strong> ${escapeHtml(item.file_path)}${item.line ? `:${item.line}` : ''}</p>` : ''}
                    <p style="margin: 0 0 8px 0; font-size: 13px;"><strong>Impact:</strong> ${escapeHtml(item.impact)}</p>
                    <div style="background: #fff; padding: 10px; border-radius: 4px; font-size: 13px;">${escapeHtml(item.analysis)}</div>
                    ${item.code_snippet ? `<pre style="background: #1f2937; color: #e5e7eb; padding: 10px; border-radius: 4px; font-size: 11px; overflow-x: auto; margin-top: 10px;">${escapeHtml(item.code_snippet)}</pre>` : ''}
                </div>`
            })
            html += `</div>`
        }
        
        // Findings Summary Tables
        const addFindingsTable = (findings: any[], title: string, type: string) => {
            if (!findings || findings.length === 0) return ''
            
            let tableHtml = `
            <div style="margin-bottom: 25px; page-break-inside: avoid;">
                <h3 style="color: #374151; font-size: 16px; margin-bottom: 10px;">${title} (${findings.length})</h3>
                <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                    <thead>
                        <tr style="background: #f3f4f6;">
                            <th style="border: 1px solid #e5e7eb; padding: 8px; text-align: left;">Severity</th>
                            <th style="border: 1px solid #e5e7eb; padding: 8px; text-align: left;">Title</th>
                            <th style="border: 1px solid #e5e7eb; padding: 8px; text-align: left;">Location</th>
                        </tr>
                    </thead>
                    <tbody>`
            
            findings.slice(0, 20).forEach(f => {
                const sevColors: Record<string, string> = {
                    critical: '#fef2f2', high: '#fff7ed', medium: '#fefce8', low: '#f0fdf4'
                }
                const bgColor = sevColors[f.severity?.toLowerCase()] || '#fff'
                tableHtml += `
                        <tr style="background: ${bgColor};">
                            <td style="border: 1px solid #e5e7eb; padding: 6px;">${f.severity || 'N/A'}</td>
                            <td style="border: 1px solid #e5e7eb; padding: 6px;">${escapeHtml(f.title || f.description || 'N/A')}</td>
                            <td style="border: 1px solid #e5e7eb; padding: 6px;">${escapeHtml(f.file_path || 'N/A')}</td>
                        </tr>`
            })
            
            if (findings.length > 20) {
                tableHtml += `<tr><td colspan="3" style="border: 1px solid #e5e7eb; padding: 6px; text-align: center; color: #6b7280;">... and ${findings.length - 20} more findings</td></tr>`
            }
            
            tableHtml += `</tbody></table></div>`
            return tableHtml
        }
        
        html += `<h2 style="color: #1e40af; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; font-size: 20px; margin-top: 30px;">Findings Summary</h2>`
        html += addFindingsTable(data.findings?.secrets, 'Secrets', 'secrets')
        html += addFindingsTable(data.findings?.sast, 'SAST', 'sast')
        html += addFindingsTable(data.findings?.infrastructure, 'Infrastructure', 'infrastructure')
        html += addFindingsTable(data.findings?.dependencies, 'Dependencies', 'dependencies')
        
        // Footer
        html += `
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; text-align: center; color: #9ca3af; font-size: 11px;">
                <p>Generated by AuditGH Security Assessment Platform</p>
                <p>Report ID: ${data.report_id || 'N/A'}</p>
            </div>
        </div>`
        
        return html
    }

    const generateDOCX = async (data: ReportData, filename: string) => {
        // Generate HTML content and convert to DOCX-compatible format
        const htmlContent = buildPDFHtml(data)
        
        // Create a complete HTML document for Word
        const docxHtml = `
<!DOCTYPE html>
<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40">
<head>
<meta charset="utf-8">
<title>Security Assessment Report - ${data.project?.name || projectName}</title>
<!--[if gte mso 9]>
<xml>
<w:WordDocument>
<w:View>Print</w:View>
<w:Zoom>100</w:Zoom>
<w:DoNotOptimizeForBrowser/>
</w:WordDocument>
</xml>
<![endif]-->
<style>
@page { size: A4; margin: 2cm; }
body { font-family: Calibri, Arial, sans-serif; font-size: 11pt; line-height: 1.5; }
h1 { font-size: 24pt; color: #1e40af; }
h2 { font-size: 16pt; color: #1e40af; border-bottom: 2px solid #e5e7eb; padding-bottom: 4pt; }
h3 { font-size: 14pt; color: #374151; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #e5e7eb; padding: 6pt; }
th { background-color: #f3f4f6; }
.critical { background-color: #fef2f2; }
.high { background-color: #fff7ed; }
.medium { background-color: #fefce8; }
.low { background-color: #f0fdf4; }
</style>
</head>
<body>
${htmlContent}
</body>
</html>`
        
        const blob = new Blob([docxHtml], { type: 'application/vnd.ms-word' })
        
        // Try to use File System Access API for native "Save As" dialog
        if ('showSaveFilePicker' in window) {
            try {
                const handle = await (window as any).showSaveFilePicker({
                    suggestedName: `${filename}.doc`,
                    types: [{
                        description: 'Word Document',
                        accept: { 'application/msword': ['.doc'] }
                    }]
                })
                const writable = await handle.createWritable()
                await writable.write(blob)
                await writable.close()
                return
            } catch (err: any) {
                if (err.name === 'AbortError') return
            }
        }
        
        // Fallback: traditional download
        const url = URL.createObjectURL(blob)
        const a = document.createElement("a")
        a.href = url
        a.download = `${filename}.doc`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
    }

    return (
        <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
            <DialogContent 
                className="max-w-[90vw] w-[90vw] h-[85vh] max-h-[85vh] p-0 gap-0 overflow-hidden"
                style={{ maxWidth: '90vw', width: '90vw' }}
            >
                {/* Fixed Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b bg-background sticky top-0 z-10">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600">
                            <Shield className="h-6 w-6 text-white" />
                        </div>
                        <div>
                            <DialogTitle className="text-xl font-bold">
                                Security Assessment Report
                            </DialogTitle>
                            <p className="text-sm text-muted-foreground">{projectName}</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-2">
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <Button variant="outline" disabled={!reportData || generating}>
                                    <Download className="h-4 w-4 mr-2" />
                                    Export
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                                <DropdownMenuItem onClick={() => handleExportClick("pdf")}>
                                    <FileText className="h-4 w-4 mr-2" />
                                    PDF Document
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => handleExportClick("docx")}>
                                    <FileType className="h-4 w-4 mr-2" />
                                    Word Document (DOCX)
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => handleExportClick("markdown")}>
                                    <FileText className="h-4 w-4 mr-2" />
                                    Markdown
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => handleExportClick("json")}>
                                    <FileJson className="h-4 w-4 mr-2" />
                                    JSON
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => handleExportClick("csv")}>
                                    <FileSpreadsheet className="h-4 w-4 mr-2" />
                                    CSV (Findings)
                                </DropdownMenuItem>
                            </DropdownMenuContent>
                        </DropdownMenu>
                        <Button variant="ghost" size="icon" onClick={onClose}>
                            <X className="h-4 w-4" />
                        </Button>
                    </div>
                </div>

                {/* Content */}
                <ScrollArea className="flex-1 h-[calc(85vh-80px)]">
                    <div ref={reportRef} className="p-6">
                        {generating ? (
                            <div className="flex flex-col items-center justify-center h-96 gap-4">
                                <div className="relative">
                                    <Loader2 className="h-12 w-12 animate-spin text-blue-500" />
                                </div>
                                <div className="text-center">
                                    <h3 className="text-lg font-semibold">Generating Report</h3>
                                    <p className="text-sm text-muted-foreground">
                                        Comprehensive security assessment with actionable insights
                                    </p>
                                </div>
                            </div>
                        ) : error ? (
                            <div className="flex flex-col items-center justify-center h-96 gap-4">
                                <AlertCircle className="h-12 w-12 text-red-500" />
                                <div className="text-center">
                                    <h3 className="text-lg font-semibold text-red-500">Error Generating Report</h3>
                                    <p className="text-sm text-muted-foreground">{error}</p>
                                </div>
                                <Button onClick={generateReport}>Try Again</Button>
                            </div>
                        ) : reportData ? (
                            <div className="space-y-8">
                                {/* Risk Score Overview */}
                                <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                                    <Card className="md:col-span-2 bg-gradient-to-br from-slate-900 to-slate-800 text-white">
                                        <CardHeader className="pb-2">
                                            <CardTitle className="text-lg">Overall Risk Score</CardTitle>
                                        </CardHeader>
                                        <CardContent>
                                            <div className="flex items-center gap-4">
                                                <div className={`text-5xl font-bold ${getRiskColor(reportData.risk_score?.overall || 0)}`}>
                                                    {reportData.risk_score?.overall || 0}
                                                </div>
                                                <div className="flex-1">
                                                    <Progress 
                                                        value={reportData.risk_score?.overall || 0} 
                                                        className="h-3"
                                                    />
                                                    <p className="text-xs text-slate-400 mt-1">
                                                        {reportData.risk_score?.overall >= 80 ? "Critical Risk" :
                                                         reportData.risk_score?.overall >= 60 ? "High Risk" :
                                                         reportData.risk_score?.overall >= 40 ? "Medium Risk" : "Low Risk"}
                                                    </p>
                                                </div>
                                            </div>
                                        </CardContent>
                                    </Card>

                                    {[
                                        { label: "Secrets", score: reportData.risk_score?.secrets, icon: Lock },
                                        { label: "SAST", score: reportData.risk_score?.sast, icon: Bug },
                                        { label: "Infrastructure", score: reportData.risk_score?.infrastructure, icon: Server },
                                    ].map((item) => (
                                        <Card key={item.label}>
                                            <CardContent className="pt-4">
                                                <div className="flex items-center justify-between">
                                                    <div className="flex items-center gap-2">
                                                        <item.icon className="h-4 w-4 text-muted-foreground" />
                                                        <span className="text-sm font-medium">{item.label}</span>
                                                    </div>
                                                    <span className={`text-2xl font-bold ${getRiskColor(item.score || 0)}`}>
                                                        {item.score || 0}
                                                    </span>
                                                </div>
                                                <Progress value={item.score || 0} className="h-2 mt-2" />
                                            </CardContent>
                                        </Card>
                                    ))}
                                </div>

                                {/* Executive Summary */}
                                <Card>
                                    <CardHeader>
                                        <div className="flex items-center gap-2">
                                            <CardTitle>Executive Summary</CardTitle>
                                        </div>
                                        <CardDescription>
                                            Comprehensive overview of security posture
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent>
                                        <div className="prose prose-sm dark:prose-invert max-w-none">
                                            <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                                {reportData.executive_summary || "No executive summary available."}
                                            </ReactMarkdown>
                                        </div>
                                    </CardContent>
                                </Card>

                                {/* System Architecture */}
                                {reportData.architecture?.report && (
                                    <Card>
                                        <CardHeader>
                                            <div className="flex items-center gap-2">
                                                <Server className="h-5 w-5 text-blue-500" />
                                                <CardTitle>System Architecture</CardTitle>
                                            </div>
                                            <CardDescription>
                                                Technical architecture and design overview
                                            </CardDescription>
                                        </CardHeader>
                                        <CardContent className="space-y-4">
                                            {reportData.architecture.diagram_base64 && (
                                                <div className="flex justify-center p-4 bg-white rounded-lg">
                                                    <img 
                                                        src={`data:image/png;base64,${reportData.architecture.diagram_base64}`}
                                                        alt="Architecture Diagram"
                                                        className="max-w-full h-auto"
                                                    />
                                                </div>
                                            )}
                                            <div className="prose prose-sm dark:prose-invert max-w-none">
                                                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                                    {reportData.architecture.report}
                                                </ReactMarkdown>
                                            </div>
                                            {reportData.architecture.insights && (
                                                <div className="mt-4 p-4 bg-purple-50 dark:bg-purple-950/30 rounded-lg border border-purple-200 dark:border-purple-800">
                                                    <div className="flex items-center gap-2 mb-2">
                                                        <Sparkles className="h-4 w-4 text-purple-500" />
                                                        <span className="font-semibold text-purple-700 dark:text-purple-300">Insights</span>
                                                    </div>
                                                    <p className="text-sm text-purple-800 dark:text-purple-200">
                                                        {reportData.architecture.insights}
                                                    </p>
                                                </div>
                                            )}
                                        </CardContent>
                                    </Card>
                                )}

                                {/* Project Insights */}
                                <Card>
                                    <CardHeader>
                                        <div className="flex items-center gap-2">
                                            <TrendingUp className="h-5 w-5 text-green-500" />
                                            <CardTitle>Project Insights</CardTitle>
                                        </div>
                                        <CardDescription>
                                            Development patterns, contributors, and context
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent>
                                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                            {/* Contributors */}
                                            <div className="space-y-2">
                                                <div className="flex items-center gap-2">
                                                    <Users className="h-4 w-4 text-muted-foreground" />
                                                    <span className="font-medium">Contributors</span>
                                                </div>
                                                <div className="text-3xl font-bold">
                                                    {reportData.project_insights?.contributor_count || 0}
                                                </div>
                                                <p className="text-sm text-muted-foreground">
                                                    {reportData.project_insights?.contributor_analysis || "No analysis available"}
                                                </p>
                                            </div>

                                            {/* Languages */}
                                            <div className="space-y-2">
                                                <div className="flex items-center gap-2">
                                                    <Code className="h-4 w-4 text-muted-foreground" />
                                                    <span className="font-medium">Languages</span>
                                                </div>
                                                <div className="space-y-1">
                                                    {reportData.project_insights?.language_breakdown && 
                                                        Object.entries(reportData.project_insights.language_breakdown)
                                                            .slice(0, 5)
                                                            .map(([lang, pct]) => (
                                                                <div key={lang} className="flex items-center gap-2">
                                                                    <div className="flex-1">
                                                                        <div className="flex justify-between text-sm">
                                                                            <span>{lang}</span>
                                                                            <span>{pct}%</span>
                                                                        </div>
                                                                        <Progress value={pct as number} className="h-1" />
                                                                    </div>
                                                                </div>
                                                            ))
                                                    }
                                                </div>
                                            </div>

                                            {/* Development Evaluation */}
                                            <div className="space-y-2">
                                                <div className="flex items-center gap-2">
                                                    <GitBranch className="h-4 w-4 text-muted-foreground" />
                                                    <span className="font-medium">Development</span>
                                                </div>
                                                <p className="text-sm text-muted-foreground">
                                                    {reportData.project_insights?.development_evaluation || "No evaluation available"}
                                                </p>
                                            </div>
                                        </div>
                                    </CardContent>
                                </Card>

                                {/* Critical Insights - RCE and other critical vulnerabilities */}
                                {reportData.critical_insights && reportData.critical_insights.length > 0 && (
                                    <Card className="border-4 border-red-500 dark:border-red-700 shadow-lg shadow-red-200 dark:shadow-red-900/30">
                                        <CardHeader className="bg-gradient-to-r from-red-100 to-red-50 dark:from-red-950 dark:to-red-900/50">
                                            <div className="flex items-center gap-2">
                                                <AlertCircle className="h-6 w-6 text-red-600 animate-pulse" />
                                                <CardTitle className="text-red-700 dark:text-red-400">⚠️ Critical Security Insights</CardTitle>
                                            </div>
                                            <CardDescription className="text-red-600 dark:text-red-400">
                                                Remote Code Execution and other critical vulnerabilities requiring immediate attention
                                            </CardDescription>
                                        </CardHeader>
                                        <CardContent className="pt-6">
                                            <div className="space-y-4">
                                                {reportData.critical_insights.map((insight, idx) => (
                                                    <div
                                                        key={`insight-${insight.type}-${insight.severity}-${idx}`}
                                                        className="p-4 rounded-lg border-2 border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-950/50"
                                                    >
                                                        <div className="flex items-start gap-4">
                                                            <div className="flex-shrink-0 mt-1">
                                                                <AlertCircle className="h-6 w-6 text-red-600" />
                                                            </div>
                                                            <div className="flex-1 space-y-2">
                                                                <div className="flex items-center gap-2 flex-wrap">
                                                                    <Badge className={insight.severity === 'critical' ? "bg-red-600 text-white font-bold" : "bg-orange-500 text-white font-bold"}>
                                                                        {insight.type}
                                                                    </Badge>
                                                                    <Badge variant="outline" className={insight.severity === 'critical' ? "border-red-500 text-red-600" : "border-orange-500 text-orange-600"}>
                                                                        {insight.severity?.toUpperCase() || 'CRITICAL'}
                                                                    </Badge>
                                                                </div>
                                                                <h4 className="font-semibold text-red-800 dark:text-red-300">{insight.title}</h4>
                                                                <p className="text-sm text-red-700 dark:text-red-400 font-medium">
                                                                    {insight.message}
                                                                </p>
                                                                {insight.file_path && (
                                                                    <p className="text-xs text-red-600 dark:text-red-500 font-mono">
                                                                        📁 {insight.file_path}{insight.line ? `:${insight.line}` : ''}
                                                                    </p>
                                                                )}
                                                                {/* Code snippet - Full unredacted for security analyst validation */}
                                                                {insight.code_snippet && (
                                                                    <div className="mt-3 p-3 bg-slate-900 dark:bg-slate-950 rounded border border-red-500">
                                                                        <p className="text-xs text-red-400 mb-1">Vulnerable Code (Full - Unredacted)</p>
                                                                        <pre className="text-sm font-mono text-slate-100 whitespace-pre-wrap break-all overflow-x-auto">
                                                                            {insight.code_snippet}
                                                                        </pre>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        </CardContent>
                                    </Card>
                                )}

                                {/* Critical Findings Highlight Reel */}
                                <Card className="border-2 border-red-200 dark:border-red-900">
                                    <CardHeader className="bg-gradient-to-r from-red-50 to-orange-50 dark:from-red-950/30 dark:to-orange-950/30">
                                        <div className="flex items-center gap-2">
                                            <AlertTriangle className="h-5 w-5 text-red-500" />
                                            <CardTitle>Critical Findings Highlight Reel</CardTitle>
                                        </div>
                                        <CardDescription>
                                            Curated selection of the most impactful security risks
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent className="pt-6">
                                        {reportData.highlight_reel && reportData.highlight_reel.length > 0 ? (
                                            <div className="space-y-4">
                                                {sortBySeverity(reportData.highlight_reel).map((highlight, idx) => (
                                                    <div
                                                        key={`highlight-${highlight.type}-${highlight.title}-${idx}`}
                                                        className="p-4 rounded-lg border bg-card hover:shadow-md transition-shadow"
                                                    >
                                                        <div className="flex items-start gap-4">
                                                            <div className="flex-shrink-0 mt-1">
                                                                {getSeverityIcon(highlight.severity)}
                                                            </div>
                                                            <div className="flex-1 space-y-2">
                                                                <div className="flex items-center gap-2 flex-wrap">
                                                                    <h4 className="font-semibold">{highlight.title}</h4>
                                                                    <Badge variant="outline" className="text-xs">
                                                                        {getCategoryIcon(highlight.category)}
                                                                        <span className="ml-1">{highlight.category}</span>
                                                                    </Badge>
                                                                    <Badge 
                                                                        className={
                                                                            highlight.severity === "critical" ? "bg-red-500" :
                                                                            highlight.severity === "high" ? "bg-orange-500" :
                                                                            highlight.severity === "medium" ? "bg-yellow-500" : "bg-blue-500"
                                                                        }
                                                                    >
                                                                        {highlight.severity}
                                                                    </Badge>
                                                                </div>
                                                                <div className="p-3 bg-red-50 dark:bg-red-950/30 rounded border border-red-200 dark:border-red-800">
                                                                    <p className="text-sm font-medium text-red-800 dark:text-red-200">
                                                                        <strong>Impact:</strong> {highlight.impact}
                                                                    </p>
                                                                </div>
                                                                {highlight.file_path && (
                                                                    <p className="text-xs text-muted-foreground font-mono">
                                                                        📁 {highlight.file_path}{highlight.line ? `:${highlight.line}` : ''}
                                                                    </p>
                                                                )}
                                                                {/* Code snippet - Full unredacted for security analyst validation */}
                                                                {highlight.code_snippet && (
                                                                    <div className="mt-3 p-3 bg-slate-900 dark:bg-slate-950 rounded border">
                                                                        <p className="text-xs text-slate-400 mb-1">Code Context (Full - Unredacted)</p>
                                                                        <pre className="text-sm font-mono text-slate-100 whitespace-pre-wrap break-all overflow-x-auto">
                                                                            {highlight.code_snippet}
                                                                        </pre>
                                                                    </div>
                                                                )}
                                                                <div className="prose prose-sm dark:prose-invert max-w-none">
                                                                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                                                        {highlight.analysis}
                                                                    </ReactMarkdown>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        ) : (
                                            <div className="text-center py-8 text-muted-foreground">
                                                <CheckCircle className="h-12 w-12 mx-auto mb-2 text-green-500" />
                                                <p>No critical findings identified. Great job!</p>
                                            </div>
                                        )}
                                    </CardContent>
                                </Card>

                                {/* API Security Audit Section - Only Successful Compromises */}
                                {reportData.findings?.api_audit && reportData.findings.api_audit.length > 0 && (
                                    <Card className="border-2 border-red-200 dark:border-red-900">
                                        <CardHeader className="bg-gradient-to-r from-red-50 to-orange-50 dark:from-red-950/30 dark:to-orange-950/30">
                                            <div className="flex items-center gap-2">
                                                <Globe className="h-5 w-5 text-red-500" />
                                                <CardTitle>Successful API Compromises</CardTitle>
                                            </div>
                                            <CardDescription>
                                                Endpoints where credentials successfully authenticated (2xx responses only)
                                            </CardDescription>
                                        </CardHeader>
                                        <CardContent className="pt-6">
                                            <div className="space-y-6">
                                                {/* All results are now 2xx only - sort by threat level: critical, high, medium, low, informational */}
                                                {[...reportData.findings.api_audit]
                                                    .sort((a: any, b: any) => {
                                                        const threatOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
                                                        return (threatOrder[a.threat_level] ?? 5) - (threatOrder[b.threat_level] ?? 5);
                                                    })
                                                    .map((audit: any, idx: number) => (
                                                    <div
                                                        key={`audit-${audit.endpoint}-${audit.http_method}-${idx}`}
                                                        className="p-4 rounded-lg border bg-card"
                                                    >
                                                        {/* Header - Status badges on left, status code on right */}
                                                        <div className="flex items-center justify-between gap-4 mb-3">
                                                            <div className="flex items-center gap-2 flex-wrap">
                                                                <Badge 
                                                                    className={
                                                                        audit.threat_level === "critical" ? "bg-red-500" :
                                                                        audit.threat_level === "high" ? "bg-orange-500" :
                                                                        audit.threat_level === "medium" ? "bg-yellow-500" : "bg-blue-500"
                                                                    }
                                                                >
                                                                    {audit.threat_level || "unknown"} threat
                                                                </Badge>
                                                                <Badge variant="outline">
                                                                    {audit.credential_type || "unknown"}
                                                                </Badge>
                                                                <Badge variant={audit.auth_status === "yes" ? "default" : "secondary"}>
                                                                    {audit.auth_status === "yes" ? "✓ Authenticated" : 
                                                                     audit.auth_status === "failed" ? "✗ Auth Failed" : "Not Tested"}
                                                                </Badge>
                                                                {audit.detected_service && (
                                                                    <Badge variant="outline" className="bg-purple-50 dark:bg-purple-950">
                                                                        {audit.detected_service}
                                                                    </Badge>
                                                                )}
                                                            </div>
                                                            {audit.auth_status_code && (
                                                                <div className="flex items-center gap-2">
                                                                    <span className={`text-2xl font-bold ${
                                                                        audit.auth_status_code >= 200 && audit.auth_status_code < 300 ? "text-green-500" :
                                                                        audit.auth_status_code >= 400 ? "text-red-500" : "text-yellow-500"
                                                                    }`}>
                                                                        {audit.auth_status_code}
                                                                    </span>
                                                                    {audit.auth_response_time_ms && (
                                                                        <span className="text-xs text-muted-foreground">
                                                                            {audit.auth_response_time_ms}ms
                                                                        </span>
                                                                    )}
                                                                </div>
                                                            )}
                                                        </div>
                                                        {/* URL */}
                                                        <p className="font-mono text-sm break-all text-muted-foreground mb-3">
                                                            {audit.auth_request_method || "GET"} {audit.target_url}
                                                        </p>

                                                        {/* Credential Value - Full unredacted for security analyst validation */}
                                                        {audit.credential_value && (
                                                            <div className="mb-4 p-3 bg-slate-50 dark:bg-slate-950/30 rounded border border-slate-200 dark:border-slate-800">
                                                                <p className="text-sm font-medium text-slate-800 dark:text-slate-200 mb-1">
                                                                    Credential Value
                                                                </p>
                                                                <code className="text-sm font-mono break-all text-slate-700 dark:text-slate-300 block">
                                                                    {audit.credential_value}
                                                                </code>
                                                            </div>
                                                        )}

                                                        {/* Risk Assessment */}
                                                        {audit.risk_assessment && (
                                                            <div className="mb-4 p-3 bg-amber-50 dark:bg-amber-950/30 rounded border border-amber-200 dark:border-amber-800">
                                                                <p className="text-sm font-medium text-amber-800 dark:text-amber-200 mb-1">
                                                                    Risk Assessment
                                                                </p>
                                                                <p className="text-sm text-amber-700 dark:text-amber-300">
                                                                    {audit.risk_assessment}
                                                                </p>
                                                            </div>
                                                        )}

                                                        {/* Stats Grid */}
                                                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                                                            <div className="p-2 bg-muted rounded text-center">
                                                                <p className="text-lg font-bold">{audit.discovered_paths_count || 0}</p>
                                                                <p className="text-xs text-muted-foreground">Paths Found</p>
                                                            </div>
                                                            <div className="p-2 bg-muted rounded text-center">
                                                                <p className="text-lg font-bold">{audit.hidden_paths_found || 0}</p>
                                                                <p className="text-xs text-muted-foreground">Hidden Paths</p>
                                                            </div>
                                                            <div className="p-2 bg-muted rounded text-center">
                                                                <p className="text-lg font-bold">{audit.github_repos_found || 0}</p>
                                                                <p className="text-xs text-muted-foreground">GitHub Refs</p>
                                                            </div>
                                                            <div className="p-2 bg-muted rounded text-center">
                                                                <p className="text-lg font-bold">{(audit.data_sensitivity_indicators || []).length}</p>
                                                                <p className="text-xs text-muted-foreground">Sensitivity Flags</p>
                                                            </div>
                                                        </div>

                                                        {/* Discovered Paths */}
                                                        {audit.discovered_paths && audit.discovered_paths.length > 0 && (
                                                            <div className="mb-4">
                                                                <p className="text-sm font-medium mb-2">Discovered Paths</p>
                                                                <div className="space-y-1 max-h-32 overflow-y-auto">
                                                                    {audit.discovered_paths.slice(0, 10).map((path: any, pIdx: number) => (
                                                                        <div key={pIdx} className="flex items-center gap-2 text-xs font-mono bg-muted p-1 rounded">
                                                                            <Badge variant="outline" className="text-xs">
                                                                                {path.method || "GET"}
                                                                            </Badge>
                                                                            <span className="flex-1 truncate">{path.path}</span>
                                                                            <Badge className={path.success ? "bg-green-500" : "bg-gray-500"}>
                                                                                {path.status_code || "?"}
                                                                            </Badge>
                                                                        </div>
                                                                    ))}
                                                                    {audit.discovered_paths.length > 10 && (
                                                                        <p className="text-xs text-muted-foreground">
                                                                            +{audit.discovered_paths.length - 10} more paths
                                                                        </p>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        )}

                                                        {/* OSINT Findings */}
                                                        {audit.osint_findings && audit.osint_findings.length > 0 && (
                                                            <div className="mb-4">
                                                                <p className="text-sm font-medium mb-2">OSINT Findings</p>
                                                                <div className="space-y-2 max-h-40 overflow-y-auto">
                                                                    {audit.osint_findings.slice(0, 5).map((finding: any, fIdx: number) => (
                                                                        <div key={fIdx} className="p-2 bg-muted rounded text-xs">
                                                                            <div className="flex items-center gap-2 mb-1">
                                                                                <Badge variant="outline">{finding.type}</Badge>
                                                                                <span className="text-muted-foreground">
                                                                                    {finding.relevance}% relevance
                                                                                </span>
                                                                            </div>
                                                                            <p className="text-muted-foreground">{finding.description}</p>
                                                                            {finding.url && (
                                                                                <a 
                                                                                    href={finding.url} 
                                                                                    target="_blank" 
                                                                                    rel="noopener noreferrer"
                                                                                    className="text-blue-500 hover:underline truncate block"
                                                                                >
                                                                                    {finding.url}
                                                                                </a>
                                                                            )}
                                                                        </div>
                                                                    ))}
                                                                    {audit.osint_findings.length > 5 && (
                                                                        <p className="text-xs text-muted-foreground">
                                                                            +{audit.osint_findings.length - 5} more findings
                                                                        </p>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        )}

                                                        {/* Recommendations */}
                                                        {audit.recommendations && audit.recommendations.length > 0 && (
                                                            <div>
                                                                <p className="text-sm font-medium mb-2">Recommendations</p>
                                                                <ul className="list-disc list-inside text-sm text-muted-foreground space-y-1">
                                                                    {audit.recommendations.map((rec: string, rIdx: number) => (
                                                                        <li key={rIdx}>{rec}</li>
                                                                    ))}
                                                                </ul>
                                                            </div>
                                                        )}

                                                        {/* Metadata Footer */}
                                                        <div className="mt-4 pt-3 border-t flex items-center gap-4 text-xs text-muted-foreground">
                                                            {audit.tested_at && (
                                                                <span>Tested: {new Date(audit.tested_at).toLocaleString()}</span>
                                                            )}
                                                            {audit.test_duration_seconds && (
                                                                <span>Duration: {audit.test_duration_seconds}s</span>
                                                            )}
                                                            {audit.test_mode && (
                                                                <Badge variant="outline" className="text-xs">
                                                                    {audit.test_mode} mode
                                                                </Badge>
                                                            )}
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        </CardContent>
                                    </Card>
                                )}

                                {/* Comprehensive Findings */}
                                <Card>
                                    <CardHeader>
                                        <div className="flex items-center gap-2">
                                            <FileText className="h-5 w-5 text-blue-500" />
                                            <CardTitle>Comprehensive Findings</CardTitle>
                                        </div>
                                        <CardDescription>
                                            Complete list of all security findings by category
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent>
                                        <Tabs defaultValue="secrets" className="w-full">
                                            <TabsList className="grid grid-cols-5 lg:grid-cols-9 gap-1">
                                                <TabsTrigger value="secrets" className="text-xs">
                                                    Secrets ({reportData.findings?.secrets?.length || 0})
                                                </TabsTrigger>
                                                <TabsTrigger value="sast" className="text-xs">
                                                    SAST ({reportData.findings?.sast?.length || 0})
                                                </TabsTrigger>
                                                <TabsTrigger value="infrastructure" className="text-xs">
                                                    Infra ({reportData.findings?.infrastructure?.length || 0})
                                                </TabsTrigger>
                                                <TabsTrigger value="dependencies" className="text-xs">
                                                    Deps ({reportData.findings?.dependencies?.length || 0})
                                                </TabsTrigger>
                                                <TabsTrigger value="cicd" className="text-xs">
                                                    CI/CD ({reportData.findings?.cicd?.length || 0})
                                                </TabsTrigger>
                                                <TabsTrigger value="contributors" className="text-xs">
                                                    Contributors
                                                </TabsTrigger>
                                                <TabsTrigger value="languages" className="text-xs">
                                                    Languages
                                                </TabsTrigger>
                                                <TabsTrigger value="sbom" className="text-xs">
                                                    SBOM ({reportData.findings?.sbom?.length || 0})
                                                </TabsTrigger>
                                                <TabsTrigger value="api" className="text-xs">
                                                    API ({reportData.findings?.api_audit?.length || 0})
                                                </TabsTrigger>
                                            </TabsList>

                                            <TabsContent value="secrets" className="mt-4">
                                                <FindingsTable findings={reportData.findings?.secrets || []} />
                                            </TabsContent>
                                            <TabsContent value="sast" className="mt-4">
                                                <FindingsTable findings={reportData.findings?.sast || []} />
                                            </TabsContent>
                                            <TabsContent value="infrastructure" className="mt-4">
                                                <FindingsTable findings={reportData.findings?.infrastructure || []} />
                                            </TabsContent>
                                            <TabsContent value="dependencies" className="mt-4">
                                                <FindingsTable findings={reportData.findings?.dependencies || []} />
                                            </TabsContent>
                                            <TabsContent value="cicd" className="mt-4">
                                                <FindingsTable findings={reportData.findings?.cicd || []} />
                                            </TabsContent>
                                            <TabsContent value="contributors" className="mt-4">
                                                <ContributorsTable contributors={reportData.findings?.contributors || []} />
                                            </TabsContent>
                                            <TabsContent value="languages" className="mt-4">
                                                <LanguagesTable languages={reportData.findings?.languages || {}} />
                                            </TabsContent>
                                            <TabsContent value="sbom" className="mt-4">
                                                <SBOMTable components={reportData.findings?.sbom || []} />
                                            </TabsContent>
                                            <TabsContent value="api" className="mt-4">
                                                <APIAuditTable results={reportData.findings?.api_audit || []} />
                                            </TabsContent>
                                        </Tabs>
                                    </CardContent>
                                </Card>

                                {/* Footer */}
                                <div className="text-center text-sm text-muted-foreground pt-4 border-t">
                                    <p>
                                        Report generated on {new Date(reportData.generated_at).toLocaleString()}
                                    </p>
                                </div>
                            </div>
                        ) : null}
                    </div>
                </ScrollArea>
            </DialogContent>
            
            {/* Export Filename Dialog */}
            <Dialog open={exportDialogOpen} onOpenChange={setExportDialogOpen}>
                <DialogContent className="sm:max-w-md">
                    <DialogHeader>
                        <DialogTitle>Export Report</DialogTitle>
                        <DialogDescription>
                            Enter a filename for your {exportFormat.toUpperCase()} export
                        </DialogDescription>
                    </DialogHeader>
                    <div className="grid gap-4 py-4">
                        <div className="grid gap-2">
                            <Label htmlFor="filename">Filename</Label>
                            <div className="flex items-center gap-2">
                                <Input
                                    id="filename"
                                    value={exportFilename}
                                    onChange={(e) => setExportFilename(e.target.value)}
                                    placeholder="Enter filename"
                                    className="flex-1"
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter') {
                                            confirmExport()
                                        }
                                    }}
                                />
                                <span className="text-muted-foreground">.{exportFormat}</span>
                            </div>
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setExportDialogOpen(false)}>
                            Cancel
                        </Button>
                        <Button onClick={confirmExport} disabled={!exportFilename.trim()}>
                            <Download className="h-4 w-4 mr-2" />
                            Export
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </Dialog>
    )
}

// Helper Components

function FindingsTable({ findings }: { findings: any[] }) {
    // Severity sort order: critical, high, medium, low, informational
    const severityOrder: Record<string, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        informational: 4
    }

    const sortedFindings = [...findings].sort((a, b) => {
        const aOrder = severityOrder[(a.severity || 'informational').toLowerCase()] ?? 5
        const bOrder = severityOrder[(b.severity || 'informational').toLowerCase()] ?? 5
        return aOrder - bOrder
    })

    if (!findings || findings.length === 0) {
        return (
            <div className="text-center py-8 text-muted-foreground">
                No findings in this category
            </div>
        )
    }

    return (
        <div className="space-y-4">
            {sortedFindings.slice(0, 50).map((finding, idx) => (
                <div key={finding.finding_uuid || `finding-${finding.scanner_name}-${finding.title}-${idx}`} className="border rounded-lg p-4 hover:bg-muted/30">
                    {/* Header row */}
                    <div className="flex items-center justify-between gap-4 mb-2">
                        <div className="flex items-center gap-2">
                            <Badge 
                                className={
                                    finding.severity === "critical" ? "bg-red-500" :
                                    finding.severity === "high" ? "bg-orange-500" :
                                    finding.severity === "medium" ? "bg-yellow-500" : "bg-blue-500"
                                }
                            >
                                {finding.severity}
                            </Badge>
                            <span className="font-medium">{finding.title || finding.name}</span>
                        </div>
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            {finding.is_verified_by_scanner && (
                                <Badge variant="outline" className="bg-green-50 text-green-700 dark:bg-green-950 dark:text-green-300">
                                    Verified
                                </Badge>
                            )}
                            {finding.is_validated_active && (
                                <Badge variant="outline" className="bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-300">
                                    Active
                                </Badge>
                            )}
                        </div>
                    </div>
                    
                    {/* File and line */}
                    <p className="text-sm text-muted-foreground font-mono mb-2">
                        {finding.file_path || finding.file || "-"}
                        {finding.line && `:${finding.line}`}
                    </p>
                    
                    {/* Code snippet - Full unredacted for security analyst validation */}
                    {finding.code_snippet && (
                        <div className="mt-3 p-3 bg-slate-900 dark:bg-slate-950 rounded border">
                            <p className="text-xs text-slate-400 mb-1">Code Context (Full - Unredacted)</p>
                            <pre className="text-sm font-mono text-slate-100 whitespace-pre-wrap break-all overflow-x-auto">
                                {finding.code_snippet}
                            </pre>
                        </div>
                    )}
                    
                    {/* Description if available */}
                    {finding.description && (
                        <p className="mt-2 text-sm text-muted-foreground">
                            {finding.description}
                        </p>
                    )}
                </div>
            ))}
            {findings.length > 50 && (
                <div className="px-4 py-2 bg-muted text-sm text-muted-foreground rounded">
                    Showing 50 of {findings.length} findings
                </div>
            )}
        </div>
    )
}

function ContributorsTable({ contributors }: { contributors: any[] }) {
    if (!contributors || contributors.length === 0) {
        return (
            <div className="text-center py-8 text-muted-foreground">
                No contributor data available
            </div>
        )
    }

    return (
        <div className="border rounded-lg overflow-hidden">
            <table className="w-full text-sm">
                <thead className="bg-muted">
                    <tr>
                        <th className="px-4 py-2 text-left font-medium">Contributor</th>
                        <th className="px-4 py-2 text-left font-medium">Commits</th>
                        <th className="px-4 py-2 text-left font-medium">Additions</th>
                        <th className="px-4 py-2 text-left font-medium">Deletions</th>
                    </tr>
                </thead>
                <tbody>
                    {contributors.map((c, idx) => (
                        <tr key={c.id || c.login || `contributor-${c.name}-${idx}`} className="border-t hover:bg-muted/50">
                            <td className="px-4 py-2 font-medium">{c.login || c.name}</td>
                            <td className="px-4 py-2">{c.commits || c.contributions || 0}</td>
                            <td className="px-4 py-2 text-green-600">+{c.additions || 0}</td>
                            <td className="px-4 py-2 text-red-600">-{c.deletions || 0}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    )
}

function LanguagesTable({ languages }: { languages: Record<string, number> }) {
    const entries = Object.entries(languages)
    
    if (entries.length === 0) {
        return (
            <div className="text-center py-8 text-muted-foreground">
                No language data available
            </div>
        )
    }

    return (
        <div className="space-y-2">
            {entries.map(([lang, pct]) => (
                <div key={lang} className="flex items-center gap-4">
                    <span className="w-32 font-medium">{lang}</span>
                    <div className="flex-1">
                        <Progress value={pct as number} className="h-2" />
                    </div>
                    <span className="w-16 text-right text-muted-foreground">{pct}%</span>
                </div>
            ))}
        </div>
    )
}

function SBOMTable({ components }: { components: any[] }) {
    if (!components || components.length === 0) {
        return (
            <div className="text-center py-8 text-muted-foreground">
                No SBOM data available
            </div>
        )
    }

    return (
        <div className="border rounded-lg overflow-hidden">
            <table className="w-full text-sm">
                <thead className="bg-muted">
                    <tr>
                        <th className="px-4 py-2 text-left font-medium">Component</th>
                        <th className="px-4 py-2 text-left font-medium">Version</th>
                        <th className="px-4 py-2 text-left font-medium">Type</th>
                        <th className="px-4 py-2 text-left font-medium">License</th>
                    </tr>
                </thead>
                <tbody>
                    {components.slice(0, 50).map((c, idx) => (
                        <tr key={`${c.name}-${c.version}-${idx}`} className="border-t hover:bg-muted/50">
                            <td className="px-4 py-2 font-medium">{c.name}</td>
                            <td className="px-4 py-2 font-mono text-xs">{c.version || "-"}</td>
                            <td className="px-4 py-2">{c.type || c.purl?.split(":")[0] || "-"}</td>
                            <td className="px-4 py-2">{c.license || "-"}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
            {components.length > 50 && (
                <div className="px-4 py-2 bg-muted text-sm text-muted-foreground">
                    Showing 50 of {components.length} components
                </div>
            )}
        </div>
    )
}

function APIAuditTable({ results }: { results: any[] }) {
    if (!results || results.length === 0) {
        return (
            <div className="text-center py-8 text-muted-foreground">
                No API audit data available
            </div>
        )
    }

    return (
        <div className="border rounded-lg overflow-hidden">
            <table className="w-full text-sm">
                <thead className="bg-muted">
                    <tr>
                        <th className="px-4 py-2 text-left font-medium">URL</th>
                        <th className="px-4 py-2 text-left font-medium">Credential</th>
                        <th className="px-4 py-2 text-left font-medium">Status</th>
                        <th className="px-4 py-2 text-left font-medium">Risk</th>
                    </tr>
                </thead>
                <tbody>
                    {results.slice(0, 50).map((r, idx) => (
                        <tr key={`${r.target_url || r.url}-${r.credential_type}-${idx}`} className="border-t hover:bg-muted/50">
                            <td className="px-4 py-2 font-mono text-xs truncate max-w-[200px]">{r.target_url || r.url}</td>
                            <td className="px-4 py-2">{r.credential_type || "-"}</td>
                            <td className="px-4 py-2">
                                <Badge variant={r.auth_status === "yes" ? "default" : "secondary"}>
                                    {r.auth_status === "yes" ? "Authenticated" : r.auth_status === "failed" ? "Failed" : "Not Tested"}
                                </Badge>
                            </td>
                            <td className="px-4 py-2">
                                <Badge 
                                    className={
                                        r.threat_level === "critical" ? "bg-red-500" :
                                        r.threat_level === "high" ? "bg-orange-500" :
                                        r.threat_level === "medium" ? "bg-yellow-500" : "bg-blue-500"
                                    }
                                >
                                    {r.threat_level || "unknown"}
                                </Badge>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
            {results.length > 50 && (
                <div className="px-4 py-2 bg-muted text-sm text-muted-foreground">
                    Showing 50 of {results.length} results
                </div>
            )}
        </div>
    )
}
