import * as vscode from 'vscode';
import { validatePolicy } from './validator';
import { mapDiagnostics } from './diagnostics';
import { createCompletionProvider } from './completions';
import { SimulatorPanel } from './simulator';
import { getConfig } from './config';

const DIAGNOSTIC_COLLECTION_NAME = 'vellaveto';

/** File patterns that activate validation. */
function isPolicyFile(document: vscode.TextDocument): boolean {
    const name = document.fileName;
    return (
        name.endsWith('.vellaveto.toml') ||
        name.endsWith('/vellaveto.toml') ||
        name.endsWith('\\vellaveto.toml')
    );
}

export function activate(context: vscode.ExtensionContext): void {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_COLLECTION_NAME);
    context.subscriptions.push(diagnosticCollection);

    // Command: Validate current policy file
    context.subscriptions.push(
        vscode.commands.registerCommand('vellaveto.validate', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('No active editor');
                return;
            }
            if (!isPolicyFile(editor.document)) {
                vscode.window.showWarningMessage(
                    'Current file is not a Vellaveto policy file (*.vellaveto.toml or vellaveto.toml)',
                );
                return;
            }
            await validateAndReport(editor.document, diagnosticCollection);
        }),
    );

    // Command: Open simulator
    context.subscriptions.push(
        vscode.commands.registerCommand('vellaveto.simulate', () => {
            SimulatorPanel.show(context.extensionUri);
        }),
    );

    // TOML completion provider for Vellaveto policy files
    context.subscriptions.push(
        vscode.languages.registerCompletionItemProvider(
            { language: 'toml', pattern: '**/*.vellaveto.toml' },
            createCompletionProvider(),
            '.', '=', '"',
        ),
    );
    context.subscriptions.push(
        vscode.languages.registerCompletionItemProvider(
            { language: 'toml', pattern: '**/vellaveto.toml' },
            createCompletionProvider(),
            '.', '=', '"',
        ),
    );

    // Validate on save (if enabled)
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (document) => {
            if (getConfig().validateOnSave && isPolicyFile(document)) {
                await validateAndReport(document, diagnosticCollection);
            }
        }),
    );

    // Validate on open
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(async (document) => {
            if (getConfig().validateOnSave && isPolicyFile(document)) {
                await validateAndReport(document, diagnosticCollection);
            }
        }),
    );

    // Clear diagnostics when document closes
    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument((document) => {
            diagnosticCollection.delete(document.uri);
        }),
    );

    // Validate already-open policy files
    for (const editor of vscode.window.visibleTextEditors) {
        if (isPolicyFile(editor.document)) {
            validateAndReport(editor.document, diagnosticCollection);
        }
    }
}

async function validateAndReport(
    document: vscode.TextDocument,
    diagnosticCollection: vscode.DiagnosticCollection,
): Promise<void> {
    try {
        const response = await validatePolicy(document.getText());
        const diagnostics = mapDiagnostics(document, response);
        diagnosticCollection.set(document.uri, diagnostics);

        const errors = response.summary.errors;
        const warnings = response.summary.warnings;
        if (errors > 0) {
            vscode.window.showErrorMessage(
                `Vellaveto: ${errors} error(s), ${warnings} warning(s) in policy`,
            );
        } else if (warnings > 0) {
            vscode.window.showWarningMessage(
                `Vellaveto: ${warnings} warning(s) in policy`,
            );
        }
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`Vellaveto validation failed: ${msg}`);
    }
}

export function deactivate(): void {
    // No cleanup required
}
