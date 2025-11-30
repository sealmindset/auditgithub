"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table"
import {
    Bar,
    BarChart,
    ResponsiveContainer,
    XAxis,
    YAxis,
    Tooltip,
    Legend,
    Line,
    LineChart,
} from "recharts"
import { ArrowUpRight, ShieldAlert, ShieldCheck, Shield, Activity } from "lucide-react"

// Mock Data
const severityData = [
    { name: "Critical", count: 12, fill: "#ef4444" },
    { name: "High", count: 25, fill: "#f97316" },
    { name: "Medium", count: 45, fill: "#eab308" },
    { name: "Low", count: 80, fill: "#3b82f6" },
]

const trendData = [
    { date: "Mon", findings: 145 },
    { date: "Tue", findings: 152 },
    { date: "Wed", findings: 148 },
    { date: "Thu", findings: 162 },
    { date: "Fri", findings: 158 },
    { date: "Sat", findings: 155 },
    { date: "Sun", findings: 162 },
]

const recentFindings = [
    {
        id: "VULN-2024-001",
        title: "SQL Injection in Login Handler",
        severity: "Critical",
        repo: "auth-service",
        status: "Open",
        date: "2024-11-29",
    },
    {
        id: "VULN-2024-002",
        title: "Outdated Dependency: lodash",
        severity: "High",
        repo: "frontend-app",
        status: "In Progress",
        date: "2024-11-29",
    },
    {
        id: "VULN-2024-003",
        title: "Hardcoded AWS Credentials",
        severity: "Critical",
        repo: "data-pipeline",
        status: "Assigned",
        date: "2024-11-28",
    },
    {
        id: "VULN-2024-004",
        title: "Missing CSRF Token",
        severity: "Medium",
        repo: "user-dashboard",
        status: "Open",
        date: "2024-11-28",
    },
    {
        id: "VULN-2024-005",
        title: "Insecure Direct Object Reference",
        severity: "High",
        repo: "api-gateway",
        status: "Resolved",
        date: "2024-11-27",
    },
]

export default function DashboardPage() {
    return (
        <div className="flex flex-1 flex-col gap-4 p-4 pt-0">
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Findings</CardTitle>
                        <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">162</div>
                        <p className="text-xs text-muted-foreground">
                            +12% from last week
                        </p>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
                        <Activity className="h-4 w-4 text-red-500" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold text-red-500">12</div>
                        <p className="text-xs text-muted-foreground">
                            +2 since yesterday
                        </p>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Repositories Scanned</CardTitle>
                        <Shield className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">24</div>
                        <p className="text-xs text-muted-foreground">
                            100% coverage
                        </p>
                    </CardContent>
                </Card>
                <Card>
                    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Mean Time to Resolve</CardTitle>
                        <ShieldCheck className="h-4 w-4 text-muted-foreground" />
                    </CardHeader>
                    <CardContent>
                        <div className="text-2xl font-bold">4.2 Days</div>
                        <p className="text-xs text-muted-foreground">
                            -1.5 days from last month
                        </p>
                    </CardContent>
                </Card>
            </div>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
                <Card className="col-span-4">
                    <CardHeader>
                        <CardTitle>Findings Trend</CardTitle>
                    </CardHeader>
                    <CardContent className="pl-2">
                        <ResponsiveContainer width="100%" height={350}>
                            <LineChart data={trendData}>
                                <XAxis
                                    dataKey="date"
                                    stroke="#888888"
                                    fontSize={12}
                                    tickLine={false}
                                    axisLine={false}
                                />
                                <YAxis
                                    stroke="#888888"
                                    fontSize={12}
                                    tickLine={false}
                                    axisLine={false}
                                    tickFormatter={(value) => `${value}`}
                                />
                                <Tooltip />
                                <Line
                                    type="monotone"
                                    dataKey="findings"
                                    stroke="#8884d8"
                                    strokeWidth={2}
                                    activeDot={{ r: 8 }}
                                />
                            </LineChart>
                        </ResponsiveContainer>
                    </CardContent>
                </Card>
                <Card className="col-span-3">
                    <CardHeader>
                        <CardTitle>Severity Distribution</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <ResponsiveContainer width="100%" height={350}>
                            <BarChart data={severityData}>
                                <XAxis
                                    dataKey="name"
                                    stroke="#888888"
                                    fontSize={12}
                                    tickLine={false}
                                    axisLine={false}
                                />
                                <YAxis
                                    stroke="#888888"
                                    fontSize={12}
                                    tickLine={false}
                                    axisLine={false}
                                />
                                <Tooltip />
                                <Bar dataKey="count" radius={[4, 4, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </CardContent>
                </Card>
            </div>

            <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                    <div>
                        <CardTitle>Recent Critical Findings</CardTitle>
                        <CardDescription>
                            Latest security issues requiring immediate attention.
                        </CardDescription>
                    </div>
                    <Button size="sm" className="ml-auto gap-1">
                        View All
                        <ArrowUpRight className="h-4 w-4" />
                    </Button>
                </CardHeader>
                <CardContent>
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>ID</TableHead>
                                <TableHead>Title</TableHead>
                                <TableHead>Severity</TableHead>
                                <TableHead>Repository</TableHead>
                                <TableHead>Status</TableHead>
                                <TableHead className="text-right">Date</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {recentFindings.map((finding) => (
                                <TableRow key={finding.id}>
                                    <TableCell className="font-medium">{finding.id}</TableCell>
                                    <TableCell>{finding.title}</TableCell>
                                    <TableCell>
                                        <Badge
                                            variant={
                                                finding.severity === "Critical"
                                                    ? "destructive"
                                                    : finding.severity === "High"
                                                        ? "default" // Orange isn't default, but we can style it later
                                                        : "secondary"
                                            }
                                            className={
                                                finding.severity === "High" ? "bg-orange-500 hover:bg-orange-600" : ""
                                            }
                                        >
                                            {finding.severity}
                                        </Badge>
                                    </TableCell>
                                    <TableCell>{finding.repo}</TableCell>
                                    <TableCell>{finding.status}</TableCell>
                                    <TableCell className="text-right">{finding.date}</TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </CardContent>
            </Card>
        </div>
    )
}
