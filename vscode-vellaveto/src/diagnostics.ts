import * as vscode from 'vscode';
import { ValidationFinding, ValidateResponse } from './validator';

/** Maps ValidationFinding[] to VS Code diagnostics on a document. */
export function mapDiagnostics(
    document: vscode.TextDocument,
    response: ValidateResponse,
): vscode.Diagnostic[] {
    return response.findings.map((finding) => {
        const range = findRange(document, finding);
        const severity = mapSeverity(finding.severity);
        const diagnostic = new vscode.Diagnostic(range, finding.message, severity);
        diagnostic.code = finding.code;
        diagnostic.source = 'vellaveto';
        if (finding.suggestion) {
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(document.uri, range),
                    `Suggestion: ${finding.suggestion}`,
                ),
            ];
        }
        return diagnostic;
    });
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'error':
            return vscode.DiagnosticSeverity.Error;
        case 'warning':
            return vscode.DiagnosticSeverity.Warning;
        case 'info':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Warning;
    }
}

/**
 * Attempts to locate the finding within the document.
 * If a location like "policies[2]" is given, finds the corresponding [[policies]] block.
 * If a line number is given, uses that directly.
 * Falls back to line 0 if no location is available.
 */
function findRange(document: vscode.TextDocument, finding: ValidationFinding): vscode.Range {
    const text = document.getText();
    const location = finding.location || '';

    // Try "line N" format
    const lineMatch = location.match(/line\s+(\d+)/);
    if (lineMatch) {
        const lineNo = Math.max(0, parseInt(lineMatch[1], 10) - 1);
        const safeLineNo = Math.min(lineNo, document.lineCount - 1);
        return document.lineAt(safeLineNo).range;
    }

    // Try "policies[N]" format
    const policyMatch = location.match(/policies\[(\d+)\]/);
    if (policyMatch) {
        const policyIndex = parseInt(policyMatch[1], 10);
        let count = -1;
        for (let i = 0; i < document.lineCount; i++) {
            const line = document.lineAt(i).text.trim();
            if (line === '[[policies]]') {
                count++;
                if (count === policyIndex) {
                    return document.lineAt(i).range;
                }
            }
        }
    }

    // Try finding the policy by name in the message
    const nameMatch = finding.message.match(/policy\s+"([^"]+)"/i);
    if (nameMatch) {
        const name = nameMatch[1];
        for (let i = 0; i < document.lineCount; i++) {
            if (document.lineAt(i).text.includes(`name = "${name}"`)) {
                return document.lineAt(i).range;
            }
        }
    }

    // Fallback: first line
    return document.lineAt(0).range;
}
