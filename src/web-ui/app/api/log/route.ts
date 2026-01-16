/**
 * Log Forwarding Proxy API Route
 * 
 * This server-side route receives logs from the client (browser) and forwards them
 * to Cribl Stream with the authentication token added server-side.
 * 
 * Benefits:
 * - Auth token is never exposed to client-side code
 * - No CORS issues since client talks to same origin
 * - Can add X-Forwarded-For header to preserve client IP
 */

import { NextRequest, NextResponse } from 'next/server';

const API_BASE = process.env.API_BASE || 'http://localhost:8000';

interface LogEntry {
    timestamp: string;
    level: string;
    message: string;
    source?: string;
    app_context?: {
        org_id?: string;
        org_name?: string;
        user_id?: string;
        request_id?: string;
        session_id?: string;
    };
    security_audit?: {
        action?: string;
        resource?: string;
        resource_id?: string;
        outcome?: string;
        ip_address?: string;
        user_agent?: string;
    };
    extra?: Record<string, unknown>;
}

interface CriblConfig {
    ingest_url: string | null;
    auth_token_set: boolean;
    verify_ssl: boolean;
    enabled: boolean;
}

let cachedConfig: CriblConfig | null = null;
let configFetchedAt: number = 0;
const CONFIG_CACHE_TTL = 60000; // 1 minute

async function getCriblConfig(): Promise<CriblConfig | null> {
    const now = Date.now();
    
    if (cachedConfig && (now - configFetchedAt) < CONFIG_CACHE_TTL) {
        return cachedConfig;
    }
    
    try {
        const res = await fetch(`${API_BASE}/cribl/config`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
            cache: 'no-store'
        });
        
        if (res.ok) {
            cachedConfig = await res.json();
            configFetchedAt = now;
            return cachedConfig;
        }
    } catch (error) {
        console.error('[LogProxy] Failed to fetch Cribl config:', error);
    }
    
    return null;
}

export async function POST(request: NextRequest) {
    try {
        const logEntry: LogEntry = await request.json();
        
        // Enrich log entry with server-side info
        const enrichedEntry: LogEntry = {
            ...logEntry,
            timestamp: logEntry.timestamp || new Date().toISOString(),
            source: logEntry.source || 'web-ui',
        };
        
        // Add client IP if available
        const clientIp = request.headers.get('x-forwarded-for') || 
                         request.headers.get('x-real-ip') ||
                         'unknown';
        
        if (enrichedEntry.security_audit) {
            enrichedEntry.security_audit.ip_address = clientIp;
        }
        
        // Get Cribl configuration
        const config = await getCriblConfig();
        
        if (!config || !config.enabled) {
            return NextResponse.json({ 
                status: 'disabled',
                message: 'Cribl logging is not enabled'
            });
        }
        
        if (!config.ingest_url) {
            return NextResponse.json({ 
                status: 'not_configured',
                message: 'Cribl ingest URL is not configured'
            });
        }
        
        // Forward to Cribl with auth token
        // Note: The actual auth token is stored in the backend and used there
        // We forward to our backend which then forwards to Cribl
        const forwardRes = await fetch(`${API_BASE}/cribl/forward`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Forwarded-For': clientIp,
            },
            body: JSON.stringify(enrichedEntry)
        });
        
        if (forwardRes.ok) {
            return NextResponse.json({ 
                status: 'forwarded',
                message: 'Log forwarded to Cribl'
            });
        } else {
            return NextResponse.json({ 
                status: 'error',
                message: `Forward failed: ${forwardRes.status}`
            }, { status: 500 });
        }
        
    } catch (error) {
        console.error('[LogProxy] Error processing log:', error);
        return NextResponse.json({ 
            status: 'error',
            message: 'Failed to process log entry'
        }, { status: 500 });
    }
}

export async function GET() {
    // Health check endpoint
    const config = await getCriblConfig();
    
    return NextResponse.json({
        status: 'ok',
        cribl_enabled: config?.enabled || false,
        cribl_configured: !!(config?.ingest_url && config?.auth_token_set)
    });
}
