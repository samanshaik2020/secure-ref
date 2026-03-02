import type { LogEvent, LogEventType, LogTransport, SecureRefRequest } from '../types';

let transports: LogTransport[] = [
    {
        log(event: LogEvent): void {
            const prefix = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' }[event.severity];
            console.log(
                `${prefix} [secure-ref] ${event.event} | ${event.timestamp}`,
                event.ip ? `| IP: ${event.ip}` : '',
                event.url ? `| URL: ${event.url}` : '',
                event.data ? JSON.stringify(event.data) : ''
            );
        },
    },
];

export function log(
    eventType: LogEventType,
    data?: Record<string, unknown>,
    req?: SecureRefRequest
): LogEvent {
    const event: LogEvent = {
        event: eventType,
        timestamp: new Date().toISOString(),
        severity: eventSeverity(eventType),
        ...(req && { ip: extractIp(req), userAgent: req.headers['user-agent']?.toString(), url: req.url }),
        ...(data && { data }),
    };
    for (const t of transports) {
        try { void t.log(event); } catch { /* never bubble */ }
    }
    return event;
}

export function configureLogger(newTransports: LogTransport[]): void {
    transports = newTransports;
}

function eventSeverity(event: LogEventType): LogEvent['severity'] {
    const map: Record<LogEventType, LogEvent['severity']> = {
        auth_failure: 'high',
        rate_limit_exceeded: 'medium',
        csrf_violation: 'high',
        xss_attempt: 'critical',
        sql_injection_attempt: 'critical',
        suspicious_request: 'medium',
        header_violation: 'medium',
        jwt_invalid: 'high',
        custom: 'low',
    };
    return map[event] ?? 'low';
}

function extractIp(req: SecureRefRequest): string | undefined {
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
        const ip = Array.isArray(xff) ? xff[0] : xff.split(',')[0];
        return ip?.trim();
    }
    return req.headers['x-real-ip']?.toString();
}
