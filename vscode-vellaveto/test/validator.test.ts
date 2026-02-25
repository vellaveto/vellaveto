// Tests for the offline validator (can run without VS Code API)
// These test the pure logic functions that don't depend on vscode module.

import * as assert from 'assert';

// Since we can't import the validator directly (it depends on node http),
// we test the offline validation logic inline here.

interface ValidationFinding {
    severity: 'error' | 'warning' | 'info';
    category: string;
    code: string;
    message: string;
    location?: string;
    suggestion?: string;
}

interface ValidateResponse {
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

function offlineValidate(tomlContent: string): ValidateResponse {
    const findings: ValidationFinding[] = [];

    if (!tomlContent.includes('[[policies]]')) {
        findings.push({
            severity: 'warning',
            category: 'Schema',
            code: 'OFFLINE_NO_POLICIES',
            message: 'No [[policies]] sections found.',
            suggestion: 'Add a [[policies]] section.',
        });
    }

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
        if (!policyText.includes('tool_pattern')) {
            findings.push({
                severity: 'error',
                category: 'Schema',
                code: 'OFFLINE_MISSING_TOOL_PATTERN',
                message: `Policy #${i + 1} is missing required "tool_pattern" field.`,
                location: `policies[${i}]`,
            });
        }
    }

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

// Test runner
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

    console.log('Running validator tests...\n');

    // ── Valid configs ──────────────────────────────────────────────

    test('valid policy passes validation', () => {
        const result = offlineValidate(`
[[policies]]
name = "test"
tool_pattern = "*"
priority = 100
policy_type = "Allow"
`);
        assert.strictEqual(result.valid, true);
        assert.strictEqual(result.policy_count, 1);
        assert.strictEqual(result.findings.length, 0);
    });

    test('multiple valid policies', () => {
        const result = offlineValidate(`
[[policies]]
name = "first"
tool_pattern = "*"

[[policies]]
name = "second"
tool_pattern = "read_*"
`);
        assert.strictEqual(result.valid, true);
        assert.strictEqual(result.policy_count, 2);
    });

    // ── Missing fields ────────────────────────────────────────────

    test('missing name field produces error', () => {
        const result = offlineValidate(`
[[policies]]
tool_pattern = "*"
`);
        assert.strictEqual(result.valid, false);
        const finding = result.findings.find((f) => f.code === 'OFFLINE_MISSING_NAME');
        assert.ok(finding);
        assert.strictEqual(finding!.severity, 'error');
    });

    test('missing tool_pattern produces error', () => {
        const result = offlineValidate(`
[[policies]]
name = "test"
`);
        assert.strictEqual(result.valid, false);
        const finding = result.findings.find((f) => f.code === 'OFFLINE_MISSING_TOOL_PATTERN');
        assert.ok(finding);
    });

    test('missing both name and tool_pattern produces two errors', () => {
        const result = offlineValidate(`
[[policies]]
priority = 100
`);
        assert.strictEqual(result.summary.errors, 2);
    });

    // ── No policies ───────────────────────────────────────────────

    test('empty config produces warning', () => {
        const result = offlineValidate('');
        assert.strictEqual(result.valid, true); // no errors, just warning
        assert.strictEqual(result.summary.warnings, 1);
        const finding = result.findings.find((f) => f.code === 'OFFLINE_NO_POLICIES');
        assert.ok(finding);
    });

    test('config with only comments produces warning', () => {
        const result = offlineValidate('# This is a comment\n# Another comment');
        assert.strictEqual(result.valid, true);
        assert.strictEqual(result.summary.warnings, 1);
    });

    // ── Syntax errors ─────────────────────────────────────────────

    test('unclosed string literal detected', () => {
        const result = offlineValidate(`
[[policies]]
name = "unclosed
tool_pattern = "*"
`);
        const finding = result.findings.find((f) => f.code === 'OFFLINE_UNCLOSED_QUOTE');
        assert.ok(finding);
        assert.strictEqual(finding!.severity, 'error');
    });

    test('properly quoted strings pass', () => {
        const result = offlineValidate(`
[[policies]]
name = "properly quoted"
tool_pattern = "*"
`);
        const unclosed = result.findings.find((f) => f.code === 'OFFLINE_UNCLOSED_QUOTE');
        assert.strictEqual(unclosed, undefined);
    });

    // ── Location tracking ─────────────────────────────────────────

    test('policy index in location', () => {
        const result = offlineValidate(`
[[policies]]
name = "first"
tool_pattern = "*"

[[policies]]
priority = 100
`);
        const finding = result.findings.find((f) => f.code === 'OFFLINE_MISSING_NAME');
        assert.ok(finding);
        assert.strictEqual(finding!.location, 'policies[1]');
    });

    // ── Summary statistics ────────────────────────────────────────

    test('summary counts match findings', () => {
        const result = offlineValidate(`
[[policies]]
priority = 100
`);
        assert.strictEqual(result.summary.errors, result.findings.filter((f) => f.severity === 'error').length);
        assert.strictEqual(result.summary.warnings, result.findings.filter((f) => f.severity === 'warning').length);
    });

    test('valid flag matches zero errors', () => {
        const valid = offlineValidate(`
[[policies]]
name = "test"
tool_pattern = "*"
`);
        assert.strictEqual(valid.valid, true);
        assert.strictEqual(valid.summary.errors, 0);

        const invalid = offlineValidate(`
[[policies]]
priority = 100
`);
        assert.strictEqual(invalid.valid, false);
        assert.ok(invalid.summary.errors > 0);
    });

    // ── Complex configs ───────────────────────────────────────────

    test('full preset config validates', () => {
        const result = offlineValidate(`
[[policies]]
name = "Block credential files"
tool_pattern = "*"
function_pattern = "*"
priority = 300
id = "dev:*:credential-block"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "*", op = "glob", pattern = "**/.env", on_match = "deny", on_missing = "skip" },
]

[[policies]]
name = "Default allow"
tool_pattern = "*"
function_pattern = "*"
priority = 1
id = "dev:*:default-allow"
policy_type = "Allow"

[injection]
enabled = true
blocking = false

[audit]
redaction_level = "KeysAndPatterns"
`);
        assert.strictEqual(result.valid, true);
        assert.strictEqual(result.policy_count, 2);
    });

    test('comments are ignored during validation', () => {
        const result = offlineValidate(`
# Main policy file
# Version: 1.0

[[policies]]
name = "test" # inline comment
tool_pattern = "*"
`);
        assert.strictEqual(result.valid, true);
    });

    // ── Edge cases ────────────────────────────────────────────────

    test('escaped quotes in strings are fine', () => {
        const result = offlineValidate(`
[[policies]]
name = "test with \\"quotes\\""
tool_pattern = "*"
`);
        // The escaped quotes shouldn't trigger unclosed quote detection
        assert.strictEqual(result.valid, true);
    });

    test('policy with name= (no space) is detected', () => {
        const result = offlineValidate(`
[[policies]]
name="test"
tool_pattern = "*"
`);
        assert.strictEqual(result.valid, true);
    });

    // ── Report ────────────────────────────────────────────────────

    console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
    if (failed > 0) {
        process.exit(1);
    }
}

runTests();
