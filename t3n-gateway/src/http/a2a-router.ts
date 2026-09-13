import { randomUUID } from 'node:crypto';
import express, { Router, type ErrorRequestHandler, type Request } from 'express';
import {
  A2aDecisionUnavailableError,
  A2aProviderUnavailableError,
  type A2aEvaluationResult,
  type A2aEvaluationService,
} from '../agent/a2a-service.js';
import { SensitivePromptError } from '../security/prompt-privacy-guard.js';

export const A2A_PROTOCOL_VERSION = '1.0';
const MAX_PROMPT_LENGTH = 4_000;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const RATE_LIMIT_MAX_CLIENTS = 1_000;

interface A2aJsonRpcRequest {
  readonly jsonrpc: '2.0';
  readonly id: string | number;
  readonly method: 'SendMessage';
  readonly params: {
    readonly message: {
      readonly messageId: string;
      readonly contextId?: string;
      readonly role: 'ROLE_USER';
      readonly parts: readonly [{ readonly text: string; readonly mediaType?: 'text/plain' }];
    };
  };
}

interface RateEntry { count: number; resetAt: number; }

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  const accepted = new Set(allowed);
  return Object.keys(record).every((key) => accepted.has(key));
}

function boundedIdentifier(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 128;
}

export function parseA2aRequest(value: unknown): A2aJsonRpcRequest {
  const rpc = asRecord(value);
  if (!rpc || !hasOnlyKeys(rpc, ['jsonrpc', 'id', 'method', 'params'])) throw new Error('INVALID_REQUEST');
  if (rpc.jsonrpc !== '2.0' || rpc.method !== 'SendMessage') throw new Error('UNSUPPORTED_OPERATION');
  if (!(typeof rpc.id === 'string' || (typeof rpc.id === 'number' && Number.isSafeInteger(rpc.id)))) throw new Error('INVALID_REQUEST_ID');

  const params = asRecord(rpc.params);
  if (!params || !hasOnlyKeys(params, ['message'])) throw new Error('INVALID_PARAMS');
  const message = asRecord(params.message);
  if (!message || !hasOnlyKeys(message, ['messageId', 'contextId', 'role', 'parts'])) throw new Error('INVALID_MESSAGE');
  if (!boundedIdentifier(message.messageId) || (message.contextId !== undefined && !boundedIdentifier(message.contextId))) throw new Error('INVALID_MESSAGE_ID');
  if (message.role !== 'ROLE_USER' || !Array.isArray(message.parts) || message.parts.length !== 1) throw new Error('INVALID_MESSAGE');

  const part = asRecord(message.parts[0]);
  if (!part || !hasOnlyKeys(part, ['text', 'mediaType'])) throw new Error('INVALID_PART');
  if (part.mediaType !== undefined && part.mediaType !== 'text/plain') throw new Error('UNSUPPORTED_CONTENT_TYPE');
  if (typeof part.text !== 'string') throw new Error('INVALID_PART');
  const prompt = part.text.trim();
  if (!prompt || prompt.length > MAX_PROMPT_LENGTH) throw new Error('INVALID_PROMPT');

  return {
    jsonrpc: '2.0',
    id: rpc.id,
    method: 'SendMessage',
    params: {
      message: {
        messageId: message.messageId,
        ...(message.contextId ? { contextId: message.contextId } : {}),
        role: 'ROLE_USER',
        parts: [{ text: prompt, ...(part.mediaType ? { mediaType: 'text/plain' as const } : {}) }],
      },
    },
  };
}

export function buildA2aAgentCard(publicUrl: string) {
  return {
    name: 'T3 Privacy Guard',
    description: 'External agents can request analysis and a T3N policy decision. Protected remediation remains operator-authorized and is not exposed through A2A.',
    supportedInterfaces: [{ url: publicUrl, protocolBinding: 'JSONRPC', protocolVersion: A2A_PROTOCOL_VERSION }],
    version: '1.0.0',
    capabilities: { streaming: false, pushNotifications: false, extendedAgentCard: false },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['application/json'],
    skills: [{
      id: 'privacy-guard-evaluate',
      name: 'A2A evaluation service',
      description: 'Evaluates a synthetic privacy incident request through the existing AI proposal flow and T3N policy. It never authorizes or executes remediation.',
      tags: ['privacy', 'policy', 't3n', 'evaluation'],
      examples: ['Evaluate a synthetic incident request without literal PII or credentials.'],
      inputModes: ['text/plain'],
      outputModes: ['application/json'],
    }],
  } as const;
}

function resultMessage(result: A2aEvaluationResult, contextId: string) {
  return {
    message: {
      messageId: randomUUID(),
      contextId,
      role: 'ROLE_AGENT',
      parts: [{ data: result, mediaType: 'application/json' }],
    },
  } as const;
}

function rpcError(id: string | number | null, code: number, message: string, reason: string) {
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code,
      message,
      data: [{ '@type': 'type.googleapis.com/google.rpc.ErrorInfo', reason, domain: 't3privacyguard.a2a' }],
    },
  } as const;
}

function requestVersion(request: Request): string | null {
  const header = request.get('A2A-Version');
  if (header) return header.trim();
  const query = request.query['A2A-Version'];
  return typeof query === 'string' ? query.trim() : null;
}

class FixedWindowRateLimiter {
  private readonly clients = new Map<string, RateEntry>();

  allow(client: string, now = Date.now()): { allowed: boolean; retryAfterSeconds: number } {
    const current = this.clients.get(client);
    if (!current || current.resetAt <= now) {
      if (!current && this.clients.size >= RATE_LIMIT_MAX_CLIENTS) {
        const oldest = this.clients.keys().next().value as string | undefined;
        if (oldest) this.clients.delete(oldest);
      }
      this.clients.set(client, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
      return { allowed: true, retryAfterSeconds: 0 };
    }
    if (current.count >= RATE_LIMIT_MAX_REQUESTS) {
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((current.resetAt - now) / 1_000)) };
    }
    current.count += 1;
    return { allowed: true, retryAfterSeconds: 0 };
  }
}

export function createA2aRouter(service: A2aEvaluationService, publicUrl: string): Router {
  const router = Router();
  const limiter = new FixedWindowRateLimiter();

  router.get('/.well-known/agent-card.json', (_request, response) => {
    response.set('Cache-Control', 'public, max-age=300');
    response.json(buildA2aAgentCard(publicUrl));
  });

  router.post('/a2a', express.json({ limit: '16kb', strict: true, type: ['application/json', 'application/a2a+json'] }), async (request, response) => {
    const rawId = asRecord(request.body)?.id;
    const id = typeof rawId === 'string' || typeof rawId === 'number' ? rawId : null;
    const version = requestVersion(request);
    if (version !== A2A_PROTOCOL_VERSION) {
      response.status(400).json(rpcError(id, -32009, 'A2A protocol version is not supported', 'VERSION_NOT_SUPPORTED'));
      return;
    }

    const rate = limiter.allow(request.ip || request.socket.remoteAddress || 'unknown');
    if (!rate.allowed) {
      response.set('Retry-After', String(rate.retryAfterSeconds));
      response.status(429).json(rpcError(id, -32010, 'A2A request rate limit exceeded', 'RATE_LIMITED'));
      return;
    }

    let rpc: A2aJsonRpcRequest;
    try {
      rpc = parseA2aRequest(request.body);
    } catch (error) {
      const unsupported = error instanceof Error && (error.message === 'UNSUPPORTED_OPERATION' || error.message === 'UNSUPPORTED_CONTENT_TYPE');
      response.status(400).json(rpcError(id, unsupported ? -32004 : -32602, unsupported ? 'A2A operation or content type is not supported' : 'Invalid A2A request parameters', unsupported ? 'UNSUPPORTED_OPERATION' : 'INVALID_ARGUMENT'));
      return;
    }

    try {
      const prompt = rpc.params.message.parts[0].text;
      const result = await service.evaluate(prompt);
      const contextId = rpc.params.message.contextId ?? randomUUID();
      response.json({ jsonrpc: '2.0', id: rpc.id, result: resultMessage(result, contextId) });
    } catch (error) {
      if (error instanceof SensitivePromptError) {
        response.status(400).json(rpcError(rpc.id, -32602, 'Sensitive prompt rejected', 'SENSITIVE_PROMPT_REJECTED'));
        return;
      }
      if (error instanceof A2aProviderUnavailableError) {
        response.status(503).json(rpcError(rpc.id, -32603, 'AI provider unavailable', 'PROVIDER_UNAVAILABLE'));
        return;
      }
      if (error instanceof A2aDecisionUnavailableError) {
        response.status(503).json(rpcError(rpc.id, -32603, 'T3N policy decision unavailable', 'T3N_DECISION_UNAVAILABLE'));
        return;
      }
      response.status(500).json(rpcError(rpc.id, -32603, 'A2A evaluation failed', 'INTERNAL_ERROR'));
    }
  });

  const jsonErrorHandler: ErrorRequestHandler = (error, request, response, next) => {
    const record = asRecord(error);
    if (record?.type === 'entity.too.large' || record?.type === 'entity.parse.failed') {
      response.status(record.type === 'entity.too.large' ? 413 : 400).json(rpcError(null, -32700, record.type === 'entity.too.large' ? 'A2A request body is too large' : 'Invalid JSON', record.type === 'entity.too.large' ? 'BODY_TOO_LARGE' : 'PARSE_ERROR'));
      return;
    }
    next(error);
  };
  router.use(jsonErrorHandler);

  return router;
}
