"use client"

import { useEffect, useState } from "react"
import { useParams, useRouter } from "next/navigation"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ProjectOverview } from "@/components/project-overview"
import { DataTable } from "@/components/data-table"
import { ColumnDef } from "@tanstack/react-table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ArrowLeft, Loader2 } from "lucide-react"
import Link from "next/link"
import { AiTriageDialog } from "@/components/ai-triage-dialog"
import { ArchitectureView } from "@/components/ArchitectureView"
import { ContributorsView } from "@/components/ContributorsView"
import { LanguagesView } from "@/components/LanguagesView"
import { SbomView } from "@/components/SbomView"

const API_BASE = "http://localhost:8000"

export default function ProjectPage() {
    const params = useParams()
    const router = useRouter()
    const id = params.id as string
    const [project, setProject] = useState<any>(null)
    const [secrets, setSecrets] = useState<any[]>([])
    const [sast, setSast] = useState<any[]>([])
    const [terraform, setTerraform] = useState<any[]>([])
    const [oss, setOss] = useState<any[]>([])
    const [scanRuns, setScanRuns] = useState<any[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [projRes, secretsRes, sastRes, terraformRes, ossRes, runsRes] = await Promise.all([
                    fetch(`${API_BASE}/projects/${id}`),
                    fetch(`${API_BASE}/projects/${id}/secrets`),
                    fetch(`${API_BASE}/projects/${id}/sast`),
                    fetch(`${API_BASE}/projects/${id}/terraform`),
                    fetch(`${API_BASE}/projects/${id}/oss`),
                    fetch(`${API_BASE}/projects/${id}/runs`)
                ])

                if (projRes.ok) setProject(await projRes.json())
                if (secretsRes.ok) setSecrets(await secretsRes.json())
                if (sastRes.ok) setSast(await sastRes.json())
                if (terraformRes.ok) setTerraform(await terraformRes.json())
                if (ossRes.ok) setOss(await ossRes.json())
                if (runsRes.ok) setScanRuns(await runsRes.json())
            } catch (error) {
                console.error("Failed to fetch project data:", error)
            } finally {
                setLoading(false)
            }
        }

        if (id) fetchData()
    }, [id])

    if (loading) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    if (!project) {
        return <div>Project not found</div>
    }

    const findingColumns: ColumnDef<any>[] = [
        {
            accessorKey: "severity",
            header: "Severity",
            cell: ({ row }) => {
                const severity = row.getValue("severity") as string
                return (
                    <Badge
                        className={
                            severity === "critical" ? "bg-red-500" :
                                severity === "high" ? "bg-orange-500" :
                                    severity === "medium" ? "bg-yellow-500" : "bg-blue-500"
                        }
                    >
                        {severity}
                    </Badge>
                )
            }
        },
        {
            accessorKey: "title",
            header: "Title",
            cell: ({ row }) => (
                <Link href={`/findings/${row.original.id}`} className="font-medium text-blue-600 hover:underline">
                    {row.getValue("title")}
                </Link>
            )
        },
        {
            accessorKey: "file_path",
            header: "File",
        },
        {
            accessorKey: "line",
            header: "Line",
        },
        {
            id: "actions",
            cell: ({ row }) => <AiTriageDialog finding={row.original} />
        }
    ]

    const runColumns: ColumnDef<any>[] = [
        {
            accessorKey: "status",
            header: "Status",
            cell: ({ row }) => {
                const status = row.getValue("status") as string
                return (
                    <Badge variant={status === "completed" ? "default" : "secondary"}>
                        {status}
                    </Badge>
                )
            }
        },
        {
            accessorKey: "scan_type",
            header: "Type",
        },
        {
            accessorKey: "findings_count",
            header: "Findings",
        },
        {
            accessorKey: "created_at",
            header: "Date",
            cell: ({ row }) => new Date(row.getValue("created_at")).toLocaleString()
        },
        {
            accessorKey: "duration_seconds",
            header: "Duration (s)",
        }
    ]

    return (
        <div className="flex flex-1 flex-col gap-6 p-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => router.back()}>
                    <ArrowLeft className="h-4 w-4" />
                </Button>
                <div>
                    <h1 className="text-2xl font-bold tracking-tight">{project.name}</h1>
                    <p className="text-muted-foreground">{project.description || "No description"}</p>
                </div>
            </div>

            <Tabs defaultValue="overview" className="space-y-4">
                <TabsList>
                    <TabsTrigger value="overview">Overview</TabsTrigger>
                    <TabsTrigger value="secrets">Secrets ({secrets.length})</TabsTrigger>
                    <TabsTrigger value="sast">SAST ({sast.length})</TabsTrigger>
                    <TabsTrigger value="infrastructure">Infrastructure ({terraform.length})</TabsTrigger>
                    <TabsTrigger value="dependencies">Dependencies ({oss.length})</TabsTrigger>
                    <TabsTrigger value="cicd">CI/CD</TabsTrigger>
                    <TabsTrigger value="architecture">Architecture</TabsTrigger>
                    <TabsTrigger value="contributors">Contributors</TabsTrigger>
                    <TabsTrigger value="languages">Languages</TabsTrigger>
                    <TabsTrigger value="sbom">SBOM</TabsTrigger>
                </TabsList>
                <TabsContent value="overview" className="space-y-4">
                    <ProjectOverview
                        project={project}
                        secrets={secrets}
                        sast={sast}
                        terraform={terraform}
                        oss={oss}
                    />
                </TabsContent>
                <TabsContent value="secrets">
                    <DataTable columns={findingColumns} data={secrets} searchKey="title" />
                </TabsContent>
                <TabsContent value="sast">
                    <DataTable columns={findingColumns} data={sast} searchKey="title" />
                </TabsContent>
                <TabsContent value="infrastructure">
                    <DataTable columns={findingColumns} data={terraform} searchKey="title" />
                </TabsContent>
                <TabsContent value="dependencies">
                    <DataTable columns={findingColumns} data={oss} searchKey="title" />
                </TabsContent>
                <TabsContent value="cicd">
                    <DataTable columns={runColumns} data={scanRuns} searchKey="status" />
                </TabsContent>
                <TabsContent value="architecture" className="mt-6">
                    <ArchitectureView projectId={params.id as string} />
                </TabsContent>

                <TabsContent value="contributors" className="mt-6">
                    <ContributorsView projectId={params.id as string} />
                </TabsContent>

                <TabsContent value="languages" className="mt-6">
                    <LanguagesView projectId={params.id as string} />
                </TabsContent>

                <TabsContent value="sbom" className="mt-6">
                    <SbomView projectId={params.id as string} />
                </TabsContent>
            </Tabs>
        </div>
    )
}
