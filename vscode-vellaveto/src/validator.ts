import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { getConfig } from './config';

/** Mirrors the server's ValidationFinding type. */
export interface ValidationFinding {
    severity: 'error' | 'warning' | 'info';
    category: string;
    code: string;
    message: string;
    location?: string;
    suggestion?: string;
}

export interface ValidateResponse {
    valid: boolean;
    findings: ValidationFinding[];
    summary: {
        total_policies: number;
        errors: number;
        warnings: number;
        infos: number;
        valid: boolean;
    };
    policy_count: number;
}

/**
 * Validates a TOML policy config against the Vellaveto server.
 * Falls back to basic offline validation if the server is unreachable.
 */
export async function validatePolicy(tomlContent: string): Promise<ValidateResponse> {
    const config = getConfig();

    try {
        return await validateOnServer(tomlContent, config.serverUrl, config.apiKey);
    } catch {
        // Offline fallback: basic TOML syntax checks
        return offlineValidate(tomlContent);
    }
}

async function validateOnServer(
    tomlContent: string,
    serverUrl: string,
    apiKey: string,
): Promise<ValidateResponse> {
    const url = new URL('/api/simulator/validate', serverUrl);
    const body = JSON.stringify({ config: tomlContent, strict: false });

    return new Promise((resolve, reject) => {
        const mod = url.protocol === 'https:' ? https : http;
        const req = mod.request(
            url,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(body),
                    ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
                },
                timeout: 5000,
            },
            (res) => {
                let data = '';
                res.on('data', (chunk: string) => {
                    if (data.length > 10 * 1024 * 1024) {
                        req.destroy();
                        reject(new Error('Response too large'));
                        return;
                    }
                    data += chunk;
                });
                res.on('end', () => {
                    if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                        try {
                            resolve(JSON.parse(data) as ValidateResponse);
                        } catch {
                            reject(new Error('Invalid JSON response'));
                        }
                    } else {
                        reject(new Error(`HTTP ${res.statusCode}`));
                    }
                });
            },
        );
        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
        req.write(body);
        req.end();
    });
}

/**
 * Basic offline TOML validation when server is unreachable.
 * Checks for common policy structure issues without a full TOML parser.
 */
function offlineValidate(tomlContent: string): ValidateResponse {
    const findings: ValidationFinding[] = [];

    // Check for required [[policies]] sections
    if (!tomlContent.includes('[[policies]]')) {
        findings.push({
            severity: 'warning',
            category: 'Schema',
            code: 'OFFLINE_NO_POLICIES',
            message: 'No [[policies]] sections found. A valid config needs at least one policy.',
            suggestion: 'Add a [[policies]] section with name, tool_pattern, and policy_type fields.',
        });
    }

    // Check for policies missing required fields
    const policyBlocks = tomlContent.split('[[policies]]').slice(1);
    for (let i = 0; i < policyBlocks.length; i++) {
        const block = policyBlocks[i];
        const nextSection = block.search(/\n\[(?!\[)/);
        const policyText = nextSection >= 0 ? block.substring(0, nextSection) : block;

        if (!policyText.includes('name =') && !policyText.includes('name=')) {
            findings.push({
                severity: 'error',
                category: 'Schema',
                code: 'OFFLINE_MISSING_NAME',
                message: `Policy #${i + 1} is missing required "name" field.`,
                location: `policies[${i}]`,
            });
        }
        if (!policyText.includes('tool_pattern') && !policyText.includes('tool_pattern')) {
            findings.push({
                severity: 'error',
                category: 'Schema',
                code: 'OFFLINE_MISSING_TOOL_PATTERN',
                message: `Policy #${i + 1} is missing required "tool_pattern" field.`,
                location: `policies[${i}]`,
            });
        }
    }

    // Check for unclosed quotes
    const lines = tomlContent.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line.startsWith('#') || line === '') continue;
        const quoteCount = (line.match(/(?<!\\)"/g) || []).length;
        if (quoteCount % 2 !== 0) {
            findings.push({
                severity: 'error',
                category: 'Syntax',
                code: 'OFFLINE_UNCLOSED_QUOTE',
                message: `Unclosed string literal on line ${i + 1}.`,
                location: `line ${i + 1}`,
            });
        }
    }

    return {
        valid: findings.filter((f) => f.severity === 'error').length === 0,
        findings,
        summary: {
            total_policies: policyBlocks.length,
            errors: findings.filter((f) => f.severity === 'error').length,
            warnings: findings.filter((f) => f.severity === 'warning').length,
            infos: findings.filter((f) => f.severity === 'info').length,
            valid: findings.filter((f) => f.severity === 'error').length === 0,
        },
        policy_count: policyBlocks.length,
    };
}
