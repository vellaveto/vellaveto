// Tests for diagnostic mapping logic (pure functions, no VS Code dependency)

import * as assert from 'assert';

interface ValidationFinding {
    severity: 'error' | 'warning' | 'info';
    category: string;
    code: string;
    message: string;
    location?: string;
    suggestion?: string;
}

// Test the location parsing logic extracted from diagnostics.ts
function parseLocation(location: string | undefined): { type: string; value: number } | null {
    if (!location) return null;

    const lineMatch = location.match(/line\s+(\d+)/);
    if (lineMatch) {
        return { type: 'line', value: parseInt(lineMatch[1], 10) };
    }

    const policyMatch = location.match(/policies\[(\d+)\]/);
    if (policyMatch) {
        return { type: 'policy', value: parseInt(policyMatch[1], 10) };
    }

    return null;
}

function mapSeverityStr(severity: string): string {
    switch (severity) {
        case 'error': return 'Error';
        case 'warning': return 'Warning';
        case 'info': return 'Information';
        default: return 'Warning';
    }
}

function runTests(): void {
    let passed = 0;
    let failed = 0;

    function test(name: string, fn: () => void): void {
        try {
            fn();
            passed++;
            console.log(`  PASS: ${name}`);
        } catch (e) {
            failed++;
            console.error(`  FAIL: ${name}`);
            console.error(`    ${e}`);
        }
    }

    console.log('Running diagnostics tests...\n');

    // ── Location parsing ──────────────────────────────────────────

    test('parse line location', () => {
        const result = parseLocation('line 5');
        assert.deepStrictEqual(result, { type: 'line', value: 5 });
    });

    test('parse policy index location', () => {
        const result = parseLocation('policies[2]');
        assert.deepStrictEqual(result, { type: 'policy', value: 2 });
    });

    test('parse null location', () => {
        assert.strictEqual(parseLocation(undefined), null);
        assert.strictEqual(parseLocation(''), null);
    });

    test('parse unknown location format', () => {
        assert.strictEqual(parseLocation('somewhere'), null);
    });

    // ── Severity mapping ──────────────────────────────────────────

    test('map error severity', () => {
        assert.strictEqual(mapSeverityStr('error'), 'Error');
    });

    test('map warning severity', () => {
        assert.strictEqual(mapSeverityStr('warning'), 'Warning');
    });

    test('map info severity', () => {
        assert.strictEqual(mapSeverityStr('info'), 'Information');
    });

    test('map unknown severity defaults to warning', () => {
        assert.strictEqual(mapSeverityStr('critical'), 'Warning');
    });

    // ── Finding structure ─────────────────────────────────────────

    test('finding with all fields', () => {
        const finding: ValidationFinding = {
            severity: 'error',
            category: 'Schema',
            code: 'MISSING_NAME',
            message: 'Policy is missing name',
            location: 'policies[0]',
            suggestion: 'Add a name field',
        };
        assert.ok(finding.suggestion);
        assert.strictEqual(finding.code, 'MISSING_NAME');
    });

    test('finding with minimal fields', () => {
        const finding: ValidationFinding = {
            severity: 'warning',
            category: 'BestPractice',
            code: 'LOW_PRIORITY',
            message: 'Consider higher priority',
        };
        assert.strictEqual(finding.location, undefined);
        assert.strictEqual(finding.suggestion, undefined);
    });

    // ── Report ────────────────────────────────────────────────────

    console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
    if (failed > 0) {
        process.exit(1);
    }
}

runTests();
