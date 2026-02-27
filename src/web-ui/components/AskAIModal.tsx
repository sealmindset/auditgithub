import React, { useState, useRef, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import {
  Sparkles,
  Send,
  Loader2,
  AlertCircle,
  Brain,
  Shield,
  FileText,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { API_BASE } from "@/lib/api"

interface Message {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  citations?: Citation[];
  needsClarification?: boolean;
  clarificationQuestion?: string;
  thinking?: string;
}

interface Citation {
  id: string;
  source: string;
  type: 'repository' | 'scan_result' | 'vulnerability' | 'web' | 'documentation';
  reference: string;
  excerpt?: string;
  url?: string;
}

interface AskAIModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: number;
  repositoryId: number;
  repositoryName: string;
  context?: {
    technicalOverview?: string;
    scanResults?: any[];
    vulnerabilities?: any[];
  };
}

export function AskAIModal({
  open,
  onOpenChange,
  projectId,
  repositoryId,
  repositoryName,
  context,
}: AskAIModalProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      role: 'system',
      content: `I'm your AI security architect assistant for **${repositoryName}**. I can help you understand the technical architecture, security posture, and design principles with a focus on zero-trust architecture.\n\nI have access to:\n- Repository code and structure\n- All scan results and vulnerability reports\n- AI-generated technical overview\n- External security research (when needed)\n\nFeel free to ask me anything about the security architecture, design patterns, or specific concerns you have.`,
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [expandedCitations, setExpandedCitations] = useState<Set<string>>(new Set());
  const [copiedMessageId, setCopiedMessageId] = useState<string | null>(null);
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (scrollAreaRef.current) {
      const scrollElement = scrollAreaRef.current.querySelector('[data-radix-scroll-area-viewport]');
      if (scrollElement) {
        scrollElement.scrollTop = scrollElement.scrollHeight;
      }
    }
  }, [messages]);

  // Focus textarea when modal opens
  useEffect(() => {
    if (open && textareaRef.current) {
      setTimeout(() => textareaRef.current?.focus(), 100);
    }
  }, [open]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: input.trim(),
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await fetch(`${API_BASE}/api/projects/${projectId}/repositories/${repositoryId}/ai-chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          conversation_id: conversationId,
          message: userMessage.content,
          context: context,
          focus: 'security_architecture',
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
        console.error('API Error:', errorData);
        throw new Error(errorData.detail || `API Error: ${response.status}`);
      }

      const data = await response.json();

      // Update conversation ID if this is the first message
      if (!conversationId && data.conversation_id) {
        setConversationId(data.conversation_id);
      }

      const assistantMessage: Message = {
        id: data.message_id || Date.now().toString(),
        role: 'assistant',
        content: data.content,
        timestamp: new Date(data.timestamp),
        citations: data.citations,
        needsClarification: data.needs_clarification,
        clarificationQuestion: data.clarification_question,
        thinking: data.thinking,
      };

      setMessages((prev) => [...prev, assistantMessage]);
    } catch (error) {
      console.error('Error sending message:', error);
      const errorMessage: Message = {
        id: Date.now().toString(),
        role: 'system',
        content: '⚠️ Failed to get AI response. Please try again.',
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const toggleCitation = (citationId: string) => {
    setExpandedCitations((prev) => {
      const next = new Set(prev);
      if (next.has(citationId)) {
        next.delete(citationId);
      } else {
        next.add(citationId);
      }
      return next;
    });
  };

  const copyMessage = async (messageId: string, content: string) => {
    await navigator.clipboard.writeText(content);
    setCopiedMessageId(messageId);
    setTimeout(() => setCopiedMessageId(null), 2000);
  };

  const getCitationIcon = (type: Citation['type']) => {
    switch (type) {
      case 'repository':
        return <FileText className="w-3 h-3" />;
      case 'scan_result':
      case 'vulnerability':
        return <Shield className="w-3 h-3" />;
      case 'web':
        return <ExternalLink className="w-3 h-3" />;
      case 'documentation':
        return <FileText className="w-3 h-3" />;
      default:
        return <FileText className="w-3 h-3" />;
    }
  };

  const getCitationColor = (type: Citation['type']) => {
    switch (type) {
      case 'repository':
        return 'bg-blue-500/10 text-blue-700 border-blue-200';
      case 'scan_result':
      case 'vulnerability':
        return 'bg-red-500/10 text-red-700 border-red-200';
      case 'web':
        return 'bg-purple-500/10 text-purple-700 border-purple-200';
      case 'documentation':
        return 'bg-green-500/10 text-green-700 border-green-200';
      default:
        return 'bg-gray-500/10 text-gray-700 border-gray-200';
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl h-[85vh] max-h-[85vh] flex flex-col p-0 overflow-hidden">
        {/* Header */}
        <DialogHeader className="px-6 pt-6 pb-4 border-b flex-shrink-0">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-gradient-to-br from-purple-500 to-blue-600 text-white">
              <Brain className="w-6 h-6" />
            </div>
            <div className="flex-1">
              <DialogTitle className="text-xl font-semibold flex items-center gap-2">
                Ask AI Security Architect
                <Badge variant="outline" className="font-normal">
                  <Sparkles className="w-3 h-3 mr-1" />
                  Powered by Claude
                </Badge>
              </DialogTitle>
              <DialogDescription className="mt-1">
                Discuss security architecture and zero-trust design for <strong>{repositoryName}</strong>
              </DialogDescription>
            </div>
          </div>

          {/* Context Indicators */}
          <div className="flex flex-wrap gap-2 mt-3">
            <Badge variant="secondary" className="text-xs">
              <Shield className="w-3 h-3 mr-1" />
              Zero-Trust Focus
            </Badge>
            <Badge variant="secondary" className="text-xs">
              <FileText className="w-3 h-3 mr-1" />
              Repository Context
            </Badge>
            {context?.scanResults && context.scanResults.length > 0 && (
              <Badge variant="secondary" className="text-xs">
                <AlertCircle className="w-3 h-3 mr-1" />
                {context.scanResults.length} Scan Results
              </Badge>
            )}
            {context?.vulnerabilities && context.vulnerabilities.length > 0 && (
              <Badge variant="secondary" className="text-xs">
                <AlertCircle className="w-3 h-3 mr-1" />
                {context.vulnerabilities.length} Vulnerabilities
              </Badge>
            )}
          </div>
        </DialogHeader>

        {/* Messages Area */}
        <ScrollArea ref={scrollAreaRef} className="flex-1 min-h-0 px-6 py-4 overflow-y-auto">
          <div className="space-y-6">
            {messages.map((message) => (
              <div
                key={message.id}
                className={cn(
                  'flex gap-3',
                  message.role === 'user' ? 'justify-end' : 'justify-start'
                )}
              >
                {message.role !== 'user' && (
                  <div className="flex-shrink-0">
                    {message.role === 'system' ? (
                      <div className="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center">
                        <Sparkles className="w-4 h-4 text-gray-600" />
                      </div>
                    ) : (
                      <div className="w-8 h-8 rounded-full bg-gradient-to-br from-purple-500 to-blue-600 flex items-center justify-center">
                        <Brain className="w-4 h-4 text-white" />
                      </div>
                    )}
                  </div>
                )}

                <div
                  className={cn(
                    'flex-1 max-w-[80%]',
                    message.role === 'user' && 'max-w-[70%]'
                  )}
                >
                  <div
                    className={cn(
                      'rounded-lg px-4 py-3',
                      message.role === 'user'
                        ? 'bg-blue-600 text-white ml-auto'
                        : message.role === 'system'
                        ? 'bg-gray-50 border border-gray-200'
                        : 'bg-white border border-gray-200'
                    )}
                  >
                    {/* Thinking indicator */}
                    {message.thinking && (
                      <div className="mb-2 text-xs text-gray-500 italic flex items-center gap-1">
                        <Brain className="w-3 h-3" />
                        {message.thinking}
                      </div>
                    )}

                    {/* Message content */}
                    <div
                      className={cn(
                        'prose prose-sm max-w-none',
                        message.role === 'user' && 'prose-invert'
                      )}
                      dangerouslySetInnerHTML={{
                        __html: message.content
                          .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                          .replace(/\n/g, '<br />'),
                      }}
                    />

                    {/* Clarification needed indicator */}
                    {message.needsClarification && message.clarificationQuestion && (
                      <div className="mt-3 p-2 bg-amber-50 border border-amber-200 rounded text-xs text-amber-800">
                        <div className="flex items-start gap-2">
                          <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                          <div>
                            <div className="font-medium">Clarification needed:</div>
                            <div className="mt-1">{message.clarificationQuestion}</div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Citations */}
                    {message.citations && message.citations.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-gray-200">
                        <div className="text-xs font-medium text-gray-500 mb-2">
                          References ({message.citations.length}):
                        </div>
                        <div className="space-y-2">
                          {message.citations.map((citation) => (
                            <div key={citation.id} className="text-xs">
                              <button
                                onClick={() => toggleCitation(citation.id)}
                                className={cn(
                                  'w-full flex items-center justify-between gap-2 p-2 rounded border transition-colors',
                                  getCitationColor(citation.type),
                                  'hover:bg-opacity-20'
                                )}
                              >
                                <div className="flex items-center gap-2">
                                  {getCitationIcon(citation.type)}
                                  <span className="font-medium">{citation.source}</span>
                                  <span className="text-gray-500">•</span>
                                  <span className="text-gray-600">{citation.reference}</span>
                                </div>
                                {expandedCitations.has(citation.id) ? (
                                  <ChevronUp className="w-3 h-3" />
                                ) : (
                                  <ChevronDown className="w-3 h-3" />
                                )}
                              </button>

                              {expandedCitations.has(citation.id) && citation.excerpt && (
                                <div className="mt-1 ml-6 p-2 bg-gray-50 border border-gray-200 rounded text-gray-600">
                                  {citation.excerpt}
                                  {citation.url && (
                                    <a
                                      href={citation.url}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="mt-1 inline-flex items-center gap-1 text-blue-600 hover:underline"
                                    >
                                      View source <ExternalLink className="w-3 h-3" />
                                    </a>
                                  )}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Copy button */}
                    {message.role !== 'system' && (
                      <div className="mt-2 flex justify-end">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 px-2 text-xs"
                          onClick={() => copyMessage(message.id, message.content)}
                        >
                          {copiedMessageId === message.id ? (
                            <>
                              <Check className="w-3 h-3 mr-1" />
                              Copied
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3 mr-1" />
                              Copy
                            </>
                          )}
                        </Button>
                      </div>
                    )}
                  </div>

                  <div className="mt-1 text-xs text-gray-400 px-1">
                    {message.timestamp.toLocaleTimeString()}
                  </div>
                </div>
              </div>
            ))}

            {isLoading && (
              <div className="flex gap-3">
                <div className="w-8 h-8 rounded-full bg-gradient-to-br from-purple-500 to-blue-600 flex items-center justify-center">
                  <Brain className="w-4 h-4 text-white" />
                </div>
                <div className="flex-1 max-w-[80%]">
                  <div className="rounded-lg px-4 py-3 bg-white border border-gray-200">
                    <div className="flex items-center gap-2 text-gray-500">
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span className="text-sm">Analyzing and researching...</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </ScrollArea>

        {/* Input Area */}
        <div className="px-6 py-4 border-t bg-gray-50 flex-shrink-0">
          <div className="flex gap-2">
            <Textarea
              ref={textareaRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about security architecture, zero-trust design, vulnerabilities..."
              className="min-h-[60px] max-h-[120px] resize-none"
              disabled={isLoading}
            />
            <Button
              onClick={handleSend}
              disabled={!input.trim() || isLoading}
              size="lg"
              className="px-4"
            >
              {isLoading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
            </Button>
          </div>
          <div className="mt-2 text-xs text-gray-500">
            Press <kbd className="px-1 py-0.5 bg-gray-200 rounded">Enter</kbd> to send,{' '}
            <kbd className="px-1 py-0.5 bg-gray-200 rounded">Shift+Enter</kbd> for new line
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
