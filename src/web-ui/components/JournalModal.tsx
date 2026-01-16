"use client"

import { useState, useEffect, useRef } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import {
  BookOpen,
  Send,
  Loader2,
  Sparkles,
  User,
  Bot,
  Clock,
  AlertTriangle,
  Shield,
  CheckCircle2,
  MessageSquare,
  RefreshCw,
  Pencil,
  Trash2,
  X,
  Check,
} from "lucide-react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import ReactMarkdown from "react-markdown"
import remarkGfm from "remark-gfm"

const API_BASE = "http://localhost:8000"

interface JournalEntry {
  id: string
  entry_text: string
  entry_type: string
  author_name: string
  is_ai_generated: boolean
  ai_prompt: string | null
  created_at: string
}

interface JournalModalProps {
  findingId: string
  isOpen: boolean
  onClose: () => void
  onStatusChange?: (newStatus: string | null) => void
}

export function JournalModal({ findingId, isOpen, onClose, onStatusChange }: JournalModalProps) {
  const [loading, setLoading] = useState(true)
  const [entries, setEntries] = useState<JournalEntry[]>([])
  const [investigationStatus, setInvestigationStatus] = useState<string | null>(null)
  const [investigationStartedAt, setInvestigationStartedAt] = useState<string | null>(null)
  const [newNote, setNewNote] = useState("")
  const [aiQuestion, setAiQuestion] = useState("")
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isAskingAI, setIsAskingAI] = useState(false)
  const [showAiInput, setShowAiInput] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  // Edit/Delete state
  const [editingEntryId, setEditingEntryId] = useState<string | null>(null)
  const [editingText, setEditingText] = useState("")
  const [isUpdating, setIsUpdating] = useState(false)
  const [deleteEntryId, setDeleteEntryId] = useState<string | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)

  // Fetch investigation data
  const fetchData = async () => {
    if (!findingId) return
    setLoading(true)
    try {
      const res = await fetch(`${API_BASE}/findings/${findingId}/investigation`)
      if (res.ok) {
        const data = await res.json()
        setEntries(data.journal_entries || [])
        setInvestigationStatus(data.investigation_status)
        setInvestigationStartedAt(data.investigation_started_at)
      }
    } catch (error) {
      console.error("Failed to fetch investigation data:", error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (isOpen) {
      fetchData()
    }
  }, [isOpen, findingId])

  // Auto-scroll to bottom when entries change
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [entries])

  // Update investigation status
  const handleStatusChange = async (newStatus: string) => {
    try {
      const res = await fetch(`${API_BASE}/findings/${findingId}/investigation/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus === "none" ? null : newStatus }),
      })
      if (res.ok) {
        const data = await res.json()
        setInvestigationStatus(data.investigation_status)
        setInvestigationStartedAt(data.investigation_started_at)
        onStatusChange?.(data.investigation_status)
        // Refresh to get the status change journal entry
        fetchData()
      }
    } catch (error) {
      console.error("Failed to update status:", error)
    }
  }

  // Add a journal entry
  const handleAddNote = async () => {
    if (!newNote.trim()) return
    setIsSubmitting(true)
    try {
      const res = await fetch(`${API_BASE}/findings/${findingId}/journal`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          entry_text: newNote,
          entry_type: "note",
          author_name: "Analyst",
        }),
      })
      if (res.ok) {
        setNewNote("")
        fetchData()
      }
    } catch (error) {
      console.error("Failed to add journal entry:", error)
    } finally {
      setIsSubmitting(false)
    }
  }

  // Ask AI a question
  const handleAskAI = async () => {
    if (!aiQuestion.trim()) return
    setIsAskingAI(true)
    try {
      const res = await fetch(`${API_BASE}/findings/${findingId}/journal/ask-ai`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: aiQuestion,
          author_name: "Analyst",
        }),
      })
      if (res.ok) {
        setAiQuestion("")
        setShowAiInput(false)
        fetchData()
      }
    } catch (error) {
      console.error("Failed to ask AI:", error)
    } finally {
      setIsAskingAI(false)
    }
  }

  // Start editing an entry
  const handleStartEdit = (entry: JournalEntry) => {
    setEditingEntryId(entry.id)
    setEditingText(entry.entry_text)
  }

  // Cancel editing
  const handleCancelEdit = () => {
    setEditingEntryId(null)
    setEditingText("")
  }

  // Save edited entry
  const handleSaveEdit = async () => {
    if (!editingEntryId || !editingText.trim()) return
    setIsUpdating(true)
    try {
      const res = await fetch(`${API_BASE}/findings/${findingId}/journal/${editingEntryId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          entry_text: editingText,
        }),
      })
      if (res.ok) {
        setEditingEntryId(null)
        setEditingText("")
        fetchData()
      }
    } catch (error) {
      console.error("Failed to update journal entry:", error)
    } finally {
      setIsUpdating(false)
    }
  }

  // Delete an entry
  const handleDeleteEntry = async () => {
    if (!deleteEntryId) return
    setIsDeleting(true)
    try {
      const res = await fetch(`${API_BASE}/findings/${findingId}/journal/${deleteEntryId}`, {
        method: "DELETE",
      })
      if (res.ok) {
        setDeleteEntryId(null)
        fetchData()
      }
    } catch (error) {
      console.error("Failed to delete journal entry:", error)
    } finally {
      setIsDeleting(false)
    }
  }

  // Check if an entry can be edited/deleted (only analyst notes, not system or AI)
  const canModifyEntry = (entry: JournalEntry) => {
    // Cannot modify AI-generated entries
    if (entry.is_ai_generated) return false
    // Cannot modify system-generated status changes
    if (entry.entry_type === "status_change" && entry.author_name === "System") return false
    return true
  }

  const getStatusIcon = (status: string | null) => {
    switch (status) {
      case "triage":
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />
      case "incident_response":
        return <Shield className="h-4 w-4 text-red-500" />
      case "resolved":
        return <CheckCircle2 className="h-4 w-4 text-green-500" />
      default:
        return <Clock className="h-4 w-4 text-gray-400" />
    }
  }

  const getStatusBadge = (status: string | null) => {
    switch (status) {
      case "triage":
        return <Badge className="bg-yellow-500 hover:bg-yellow-600">Triage</Badge>
      case "incident_response":
        return <Badge className="bg-red-500 hover:bg-red-600">Incident Response</Badge>
      case "resolved":
        return <Badge className="bg-green-500 hover:bg-green-600">Resolved</Badge>
      default:
        return <Badge variant="outline">No Status</Badge>
    }
  }

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr)
    return date.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    })
  }

  const getEntryTypeIcon = (entry: JournalEntry) => {
    if (entry.is_ai_generated) return <Bot className="h-4 w-4 text-purple-500" />
    if (entry.entry_type === "status_change") return <RefreshCw className="h-4 w-4 text-blue-500" />
    return <User className="h-4 w-4 text-gray-500" />
  }

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="!w-[75vw] !h-[75vh] !max-w-[75vw] !max-h-[75vh] flex flex-col p-6">
        <DialogHeader className="pb-2">
          <DialogTitle className="flex items-center gap-2">
            <BookOpen className="h-5 w-5 text-blue-500" />
            Investigation Journal
          </DialogTitle>
        </DialogHeader>

        {/* Status Selector */}
        <div className="flex items-center justify-between bg-gradient-to-r from-slate-100 to-transparent dark:from-slate-800 dark:to-transparent p-4 rounded-lg">
          <div className="flex items-center gap-3">
            {getStatusIcon(investigationStatus)}
            <div>
              <p className="text-sm font-medium">Investigation Status</p>
              {investigationStartedAt && (
                <p className="text-xs text-muted-foreground">
                  Started {formatDate(investigationStartedAt)}
                </p>
              )}
            </div>
          </div>
          <Select
            value={investigationStatus || "none"}
            onValueChange={handleStatusChange}
          >
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Set Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="none">
                <div className="flex items-center gap-2">
                  <Clock className="h-4 w-4 text-gray-400" />
                  No Status
                </div>
              </SelectItem>
              <SelectItem value="triage">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-500" />
                  Triage
                </div>
              </SelectItem>
              <SelectItem value="incident_response">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-red-500" />
                  Incident Response
                </div>
              </SelectItem>
              <SelectItem value="resolved">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  Resolved
                </div>
              </SelectItem>
            </SelectContent>
          </Select>
        </div>

        <Separator />

        {/* Journal Entries */}
        <div className="flex-1 min-h-0">
          <ScrollArea className="h-[300px] pr-4" ref={scrollRef}>
            {loading ? (
              <div className="flex items-center justify-center h-32">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : entries.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-32 text-muted-foreground">
                <MessageSquare className="h-8 w-8 mb-2 opacity-50" />
                <p>No journal entries yet</p>
                <p className="text-sm">Start by adding a note or asking AI for help</p>
              </div>
            ) : (
              <div className="space-y-4">
                {[...entries].reverse().map((entry) => (
                  <div
                    key={entry.id}
                    className={`p-3 rounded-lg border group ${
                      entry.is_ai_generated
                        ? "bg-gradient-to-br from-purple-50 to-blue-50 dark:from-purple-950/20 dark:to-blue-950/20 border-purple-200 dark:border-purple-800"
                        : entry.entry_type === "status_change"
                        ? "bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800"
                        : "bg-card border-border"
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      {getEntryTypeIcon(entry)}
                      <span className="text-sm font-medium">{entry.author_name}</span>
                      <span className="text-xs text-muted-foreground ml-auto mr-2">
                        {formatDate(entry.created_at)}
                      </span>
                      {/* Edit/Delete buttons - only show for modifiable entries */}
                      {canModifyEntry(entry) && editingEntryId !== entry.id && (
                        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={() => handleStartEdit(entry)}
                            title="Edit entry"
                          >
                            <Pencil className="h-3.5 w-3.5 text-muted-foreground hover:text-foreground" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={() => setDeleteEntryId(entry.id)}
                            title="Delete entry"
                          >
                            <Trash2 className="h-3.5 w-3.5 text-muted-foreground hover:text-destructive" />
                          </Button>
                        </div>
                      )}
                    </div>
                    {entry.is_ai_generated && entry.ai_prompt && (
                      <div className="mb-2 p-2 bg-white/50 dark:bg-black/20 rounded text-sm">
                        <span className="text-muted-foreground">Question: </span>
                        {entry.ai_prompt}
                      </div>
                    )}
                    {/* Edit mode */}
                    {editingEntryId === entry.id ? (
                      <div className="space-y-2">
                        <Textarea
                          value={editingText}
                          onChange={(e) => setEditingText(e.target.value)}
                          className="min-h-[100px] resize-none"
                          autoFocus
                        />
                        <div className="flex items-center gap-2 justify-end">
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8"
                            onClick={handleCancelEdit}
                            disabled={isUpdating}
                            title="Cancel"
                          >
                            <X className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-green-600 hover:text-green-700 hover:bg-green-50"
                            onClick={handleSaveEdit}
                            disabled={!editingText.trim() || isUpdating}
                            title="Save changes"
                          >
                            {isUpdating ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <Check className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                      </div>
                    ) : (
                      <div className="prose prose-sm dark:prose-invert max-w-none">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>
                          {entry.entry_text}
                        </ReactMarkdown>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>
        </div>

        <Separator />

        {/* Input Section */}
        <div className="space-y-3">
          {/* Note Input */}
          <div className="flex gap-2">
            <Textarea
              placeholder="Add a journal note..."
              value={newNote}
              onChange={(e) => setNewNote(e.target.value)}
              className="min-h-[220px] resize-none"
              onKeyDown={(e) => {
                if (e.key === "Enter" && e.metaKey) {
                  handleAddNote()
                }
              }}
            />
            <Button
              onClick={handleAddNote}
              disabled={!newNote.trim() || isSubmitting}
              className="self-end"
            >
              {isSubmitting ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Send className="h-4 w-4" />
              )}
            </Button>
          </div>

          {/* AI Assistant Section */}
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowAiInput(!showAiInput)}
              className={showAiInput ? "bg-purple-100 dark:bg-purple-900/20" : ""}
            >
              <Sparkles className="h-4 w-4 mr-2 text-purple-500" />
              Ask AI Assistant
            </Button>
            {showAiInput && (
              <div className="flex-1 flex gap-2">
                <Textarea
                  placeholder="Ask AI a question about this finding..."
                  value={aiQuestion}
                  onChange={(e) => setAiQuestion(e.target.value)}
                  className="min-h-[40px] resize-none text-sm"
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && e.metaKey) {
                      handleAskAI()
                    }
                  }}
                />
                <Button
                  onClick={handleAskAI}
                  disabled={!aiQuestion.trim() || isAskingAI}
                  variant="secondary"
                  className="self-end bg-gradient-to-r from-purple-500 to-blue-500 text-white hover:from-purple-600 hover:to-blue-600"
                >
                  {isAskingAI ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <>
                      <Sparkles className="h-4 w-4 mr-1" />
                      Ask
                    </>
                  )}
                </Button>
              </div>
            )}
          </div>
        </div>
      </DialogContent>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deleteEntryId} onOpenChange={(open) => !open && setDeleteEntryId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Journal Entry</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this journal entry? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isDeleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteEntry}
              disabled={isDeleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {isDeleting ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <Trash2 className="h-4 w-4 mr-2" />
              )}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Dialog>
  )
}
