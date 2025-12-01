"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Switch } from "@/components/ui/switch"
import { Loader2, CheckCircle2, XCircle } from "lucide-react"
import { useToast } from "@/components/ui/use-toast"

const API_BASE = "http://localhost:8000"

export default function SettingsPage() {
    const [loading, setLoading] = useState(false)
    const [saving, setSaving] = useState(false)
    const [verifyingOpenAI, setVerifyingOpenAI] = useState(false)
    const [verifyingJira, setVerifyingJira] = useState(false)

    const [openaiKey, setOpenaiKey] = useState("")
    const [jiraUrl, setJiraUrl] = useState("")
    const [jiraEmail, setJiraEmail] = useState("")
    const [jiraToken, setJiraToken] = useState("")

    const [openaiStatus, setOpenaiStatus] = useState<{ valid: boolean, message: string } | null>(null)
    const [jiraStatus, setJiraStatus] = useState<{ valid: boolean, message: string } | null>(null)

    useEffect(() => {
        const fetchSettings = async () => {
            setLoading(true)
            try {
                const res = await fetch(`${API_BASE}/settings/`)
                if (res.ok) {
                    const data = await res.json()
                    setOpenaiKey(data.OPENAI_API_KEY || "")
                    setJiraUrl(data.JIRA_URL || "")
                    setJiraEmail(data.JIRA_EMAIL || "")
                    setJiraToken(data.JIRA_API_TOKEN || "")
                }
            } catch (error) {
                console.error("Failed to fetch settings:", error)
            } finally {
                setLoading(false)
            }
        }
        fetchSettings()
    }, [])

    const handleSave = async () => {
        setSaving(true)
        try {
            const res = await fetch(`${API_BASE}/settings/`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    openai_api_key: openaiKey,
                    jira_url: jiraUrl,
                    jira_email: jiraEmail,
                    jira_api_token: jiraToken
                })
            })

            if (res.ok) {
                alert("Settings saved successfully!")
            } else {
                alert("Failed to save settings.")
            }
        } catch (error) {
            console.error("Failed to save settings:", error)
            alert("Error saving settings.")
        } finally {
            setSaving(false)
        }
    }

    const verifyOpenAI = async () => {
        setVerifyingOpenAI(true)
        setOpenaiStatus(null)
        try {
            const res = await fetch(`${API_BASE}/settings/verify/openai`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ token: openaiKey })
            })
            const data = await res.json()
            setOpenaiStatus(data)
        } catch (error) {
            setOpenaiStatus({ valid: false, message: "Verification request failed" })
        } finally {
            setVerifyingOpenAI(false)
        }
    }

    const verifyJira = async () => {
        setVerifyingJira(true)
        setJiraStatus(null)
        try {
            const res = await fetch(`${API_BASE}/settings/verify/jira`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    token: jiraToken,
                    url: jiraUrl,
                    email: jiraEmail
                })
            })
            const data = await res.json()
            setJiraStatus(data)
        } catch (error) {
            setJiraStatus({ valid: false, message: "Verification request failed" })
        } finally {
            setVerifyingJira(false)
        }
    }

    if (loading) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    return (
        <div className="flex flex-1 flex-col gap-6 p-6">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
                <p className="text-muted-foreground">
                    Manage your platform configuration and integrations.
                </p>
            </div>

            <Tabs defaultValue="general" className="space-y-4">
                <TabsList>
                    <TabsTrigger value="general">General</TabsTrigger>
                    <TabsTrigger value="integrations">Integrations</TabsTrigger>
                    <TabsTrigger value="notifications">Notifications</TabsTrigger>
                </TabsList>

                <TabsContent value="general" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>General Configuration</CardTitle>
                            <CardDescription>
                                Configure general platform settings.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>Automatic Scanning</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Automatically scan repositories on push events.
                                    </p>
                                </div>
                                <Switch />
                            </div>
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>AI Analysis</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Enable AI-powered triage and remediation suggestions.
                                    </p>
                                </div>
                                <Switch defaultChecked />
                            </div>
                        </CardContent>
                    </Card>
                </TabsContent>

                <TabsContent value="integrations" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>OpenAI Integration</CardTitle>
                            <CardDescription>
                                Configure OpenAI API key for AI features.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="space-y-2">
                                <Label htmlFor="openai-key">API Key</Label>
                                <div className="flex gap-2">
                                    <Input
                                        id="openai-key"
                                        type="password"
                                        placeholder="sk-..."
                                        value={openaiKey}
                                        onChange={(e) => setOpenaiKey(e.target.value)}
                                    />
                                    <Button variant="secondary" onClick={verifyOpenAI} disabled={verifyingOpenAI || !openaiKey}>
                                        {verifyingOpenAI ? <Loader2 className="h-4 w-4 animate-spin" /> : "Verify"}
                                    </Button>
                                </div>
                                {openaiStatus && (
                                    <div className={`flex items-center gap-2 text-sm ${openaiStatus.valid ? "text-green-600" : "text-red-600"}`}>
                                        {openaiStatus.valid ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
                                        {openaiStatus.message}
                                    </div>
                                )}
                            </div>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle>Jira Integration</CardTitle>
                            <CardDescription>
                                Connect to Jira for ticket management.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="grid gap-4">
                                <div className="grid gap-2">
                                    <Label htmlFor="jira-url">Jira URL</Label>
                                    <Input
                                        id="jira-url"
                                        placeholder="https://your-domain.atlassian.net"
                                        value={jiraUrl}
                                        onChange={(e) => setJiraUrl(e.target.value)}
                                    />
                                </div>
                                <div className="grid gap-2">
                                    <Label htmlFor="jira-email">Email</Label>
                                    <Input
                                        id="jira-email"
                                        placeholder="user@example.com"
                                        value={jiraEmail}
                                        onChange={(e) => setJiraEmail(e.target.value)}
                                    />
                                </div>
                                <div className="grid gap-2">
                                    <Label htmlFor="jira-token">API Token</Label>
                                    <div className="flex gap-2">
                                        <Input
                                            id="jira-token"
                                            type="password"
                                            placeholder="Jira API Token"
                                            value={jiraToken}
                                            onChange={(e) => setJiraToken(e.target.value)}
                                        />
                                        <Button variant="secondary" onClick={verifyJira} disabled={verifyingJira || !jiraToken || !jiraUrl || !jiraEmail}>
                                            {verifyingJira ? <Loader2 className="h-4 w-4 animate-spin" /> : "Verify"}
                                        </Button>
                                    </div>
                                    {jiraStatus && (
                                        <div className={`flex items-center gap-2 text-sm ${jiraStatus.valid ? "text-green-600" : "text-red-600"}`}>
                                            {jiraStatus.valid ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
                                            {jiraStatus.message}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                </TabsContent>

                <TabsContent value="notifications" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>Notifications</CardTitle>
                            <CardDescription>
                                Configure how you want to be notified.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>Email Notifications</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Receive emails about critical findings.
                                    </p>
                                </div>
                                <Switch />
                            </div>
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label>Slack Notifications</Label>
                                    <p className="text-sm text-muted-foreground">
                                        Receive alerts in Slack channels.
                                    </p>
                                </div>
                                <Switch />
                            </div>
                        </CardContent>
                    </Card>
                </TabsContent>
            </Tabs>

            <div className="flex justify-end">
                <Button onClick={handleSave} disabled={saving}>
                    {saving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Save Changes
                </Button>
            </div>
        </div>
    )
}
