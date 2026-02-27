"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Loader2, Trash2, Plus, Globe, BookOpen } from "lucide-react"
import { API_BASE } from "@/lib/api"

// Type definitions
type PathWord = {
    id: string
    word: string
    category: string | null
    is_active: boolean
    created_at: string
}

type URILibraryItem = {
    id: string
    uri: string
    description: string | null
    source: string
    is_active: boolean
    created_at: string
}

export default function ApiAuditSettingsPage() {
    const [loading, setLoading] = useState(false)

    // Path Dictionary State
    const [pathWords, setPathWords] = useState<PathWord[]>([])
    const [newWord, setNewWord] = useState("")
    const [newCategory, setNewCategory] = useState("")
    const [addingWord, setAddingWord] = useState(false)

    // URI Library State
    const [uriItems, setUriItems] = useState<URILibraryItem[]>([])
    const [newUri, setNewUri] = useState("")
    const [newDescription, setNewDescription] = useState("")
    const [addingUri, setAddingUri] = useState(false)

    // Initial load
    useEffect(() => {
        fetchData()
    }, [])

    const fetchData = async () => {
        setLoading(true)
        try {
            const [wordsRes, urisRes] = await Promise.all([
                fetch(`${API_BASE}/api-audit/dictionary`),
                fetch(`${API_BASE}/api-audit/uri-library`)
            ])

            if (wordsRes.ok) setPathWords(await wordsRes.json())
            if (urisRes.ok) setUriItems(await urisRes.json())
        } catch (error) {
            console.error("Failed to fetch data:", error)
        } finally {
            setLoading(false)
        }
    }

    // Path Dictionary Handlers
    const handleAddWord = async () => {
        if (!newWord.trim()) return
        setAddingWord(true)
        try {
            const res = await fetch(`${API_BASE}/api-audit/dictionary`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ word: newWord, category: newCategory || null })
            })
            if (res.ok) {
                const item = await res.json()
                setPathWords([...pathWords, item])
                setNewWord("")
                setNewCategory("")
            } else {
                alert("Failed to add word")
            }
        } catch (error) {
            console.error("Error adding word:", error)
        } finally {
            setAddingWord(false)
        }
    }

    const handleDeleteWord = async (word: string) => {
        if (!confirm(`Are you sure you want to delete "${word}"?`)) return
        try {
            const res = await fetch(`${API_BASE}/api-audit/dictionary/${encodeURIComponent(word)}`, {
                method: "DELETE"
            })
            if (res.ok) {
                setPathWords(pathWords.filter(w => w.word !== word))
            } else {
                alert("Failed to delete word")
            }
        } catch (error) {
            console.error("Error deleting word:", error)
        }
    }

    // URI Library Handlers
    const handleAddUri = async () => {
        if (!newUri.trim()) return
        setAddingUri(true)
        try {
            const res = await fetch(`${API_BASE}/api-audit/uri-library`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ uri: newUri, description: newDescription || null, source: "manual" })
            })
            if (res.ok) {
                const item = await res.json()
                setUriItems([...uriItems, item])
                setNewUri("")
                setNewDescription("")
            } else {
                alert("Failed to add URI")
            }
        } catch (error) {
            console.error("Error adding URI:", error)
        } finally {
            setAddingUri(false)
        }
    }

    const handleDeleteUri = async (id: string) => {
        if (!confirm("Are you sure you want to delete this URI?")) return
        try {
            const res = await fetch(`${API_BASE}/api-audit/uri-library/${id}`, {
                method: "DELETE"
            })
            if (res.ok) {
                setUriItems(uriItems.filter(u => u.id !== id))
            } else {
                alert("Failed to delete URI")
            }
        } catch (error) {
            console.error("Error deleting URI:", error)
        }
    }

    if (loading && pathWords.length === 0 && uriItems.length === 0) {
        return (
            <div className="flex h-screen items-center justify-center">
                <Loader2 className="h-8 w-8 animate-spin" />
            </div>
        )
    }

    return (
        <div className="flex flex-1 flex-col gap-6 p-6">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">API Audit Settings</h1>
                <p className="text-muted-foreground">
                    Manage global dictionaries and libraries for AI discovery and fuzzing.
                </p>
            </div>

            <Tabs defaultValue="dictionary" className="space-y-4">
                <TabsList>
                    <TabsTrigger value="dictionary" className="flex items-center gap-2">
                        <BookOpen className="h-4 w-4" />
                        Path Dictionary
                    </TabsTrigger>
                    <TabsTrigger value="uri-library" className="flex items-center gap-2">
                        <Globe className="h-4 w-4" />
                        URI Library
                    </TabsTrigger>
                </TabsList>

                {/* Path Dictionary Tab */}
                <TabsContent value="dictionary" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>Path Word Dictionary</CardTitle>
                            <CardDescription>
                                Words and phrases used by the AI Agent for API path fuzzing and discovery.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            {/* Add New Word Form */}
                            <div className="flex gap-4 items-end bg-secondary/20 p-4 rounded-lg">
                                <div className="grid gap-2 flex-1">
                                    <Label htmlFor="word">Word / Phrase</Label>
                                    <Input
                                        id="word"
                                        placeholder="e.g. v1, oauth2, soap"
                                        value={newWord}
                                        onChange={(e) => setNewWord(e.target.value)}
                                        onKeyDown={(e) => e.key === 'Enter' && handleAddWord()}
                                    />
                                </div>
                                <div className="grid gap-2 w-1/3">
                                    <Label htmlFor="category">Category (Optional)</Label>
                                    <Input
                                        id="category"
                                        placeholder="e.g. common"
                                        value={newCategory}
                                        onChange={(e) => setNewCategory(e.target.value)}
                                        onKeyDown={(e) => e.key === 'Enter' && handleAddWord()}
                                    />
                                </div>
                                <Button onClick={handleAddWord} disabled={addingWord || !newWord}>
                                    {addingWord ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
                                    Add Word
                                </Button>
                            </div>

                            {/* Words Table */}
                            <div className="border rounded-md">
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>Word</TableHead>
                                            <TableHead>Category</TableHead>
                                            <TableHead>Created At</TableHead>
                                            <TableHead className="w-[100px]"></TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {pathWords.length === 0 ? (
                                            <TableRow>
                                                <TableCell colSpan={4} className="text-center h-24 text-muted-foreground">
                                                    No words found. Add some to get started.
                                                </TableCell>
                                            </TableRow>
                                        ) : (
                                            pathWords.map((item) => (
                                                <TableRow key={item.id}>
                                                    <TableCell className="font-medium">{item.word}</TableCell>
                                                    <TableCell>{item.category || "-"}</TableCell>
                                                    <TableCell>{new Date(item.created_at).toLocaleDateString()}</TableCell>
                                                    <TableCell className="text-right">
                                                        <Button
                                                            variant="ghost"
                                                            size="icon"
                                                            className="h-8 w-8 text-destructive hover:bg-destructive/10"
                                                            onClick={() => handleDeleteWord(item.word)}
                                                        >
                                                            <Trash2 className="h-4 w-4" />
                                                        </Button>
                                                    </TableCell>
                                                </TableRow>
                                            ))
                                        )}
                                    </TableBody>
                                </Table>
                            </div>
                        </CardContent>
                    </Card>
                </TabsContent>

                {/* URI Library Tab */}
                <TabsContent value="uri-library" className="space-y-4">
                    <Card>
                        <CardHeader>
                            <CardTitle>API URI Library</CardTitle>
                            <CardDescription>
                                Reference library of API URIs for AI learning and schema understanding.
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            {/* Add New URI Form */}
                            <div className="flex gap-4 items-end bg-secondary/20 p-4 rounded-lg">
                                <div className="grid gap-2 flex-1">
                                    <Label htmlFor="uri">Full URI</Label>
                                    <Input
                                        id="uri"
                                        placeholder="https://api.example.com/v1/resource"
                                        value={newUri}
                                        onChange={(e) => setNewUri(e.target.value)}
                                        onKeyDown={(e) => e.key === 'Enter' && handleAddUri()}
                                    />
                                </div>
                                <div className="grid gap-2 w-1/3">
                                    <Label htmlFor="description">Description (Optional)</Label>
                                    <Input
                                        id="description"
                                        placeholder="e.g. Production login endpoint"
                                        value={newDescription}
                                        onChange={(e) => setNewDescription(e.target.value)}
                                        onKeyDown={(e) => e.key === 'Enter' && handleAddUri()}
                                    />
                                </div>
                                <Button onClick={handleAddUri} disabled={addingUri || !newUri}>
                                    {addingUri ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
                                    Add URI
                                </Button>
                            </div>

                            {/* URIs Table */}
                            <div className="border rounded-md">
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>URI</TableHead>
                                            <TableHead>Description</TableHead>
                                            <TableHead>Source</TableHead>
                                            <TableHead>Created At</TableHead>
                                            <TableHead className="w-[100px]"></TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {uriItems.length === 0 ? (
                                            <TableRow>
                                                <TableCell colSpan={5} className="text-center h-24 text-muted-foreground">
                                                    No URIs found in library.
                                                </TableCell>
                                            </TableRow>
                                        ) : (
                                            uriItems.map((item) => (
                                                <TableRow key={item.id}>
                                                    <TableCell className="font-mono text-sm truncate max-w-[300px]" title={item.uri}>
                                                        {item.uri}
                                                    </TableCell>
                                                    <TableCell>{item.description || "-"}</TableCell>
                                                    <TableCell>
                                                        <span className="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80">
                                                            {item.source}
                                                        </span>
                                                    </TableCell>
                                                    <TableCell>{new Date(item.created_at).toLocaleDateString()}</TableCell>
                                                    <TableCell className="text-right">
                                                        <Button
                                                            variant="ghost"
                                                            size="icon"
                                                            className="h-8 w-8 text-destructive hover:bg-destructive/10"
                                                            onClick={() => handleDeleteUri(item.id)}
                                                        >
                                                            <Trash2 className="h-4 w-4" />
                                                        </Button>
                                                    </TableCell>
                                                </TableRow>
                                            ))
                                        )}
                                    </TableBody>
                                </Table>
                            </div>
                        </CardContent>
                    </Card>
                </TabsContent>
            </Tabs>
        </div>
    )
}
