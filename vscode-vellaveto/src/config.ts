import * as vscode from 'vscode';

export interface VellavetoConfig {
    serverUrl: string;
    apiKey: string;
    validateOnSave: boolean;
}

export function getConfig(): VellavetoConfig {
    const config = vscode.workspace.getConfiguration('vellaveto');
    return {
        serverUrl: config.get<string>('serverUrl', 'http://localhost:3000').replace(/\/+$/, ''),
        apiKey: config.get<string>('apiKey', ''),
        validateOnSave: config.get<boolean>('validateOnSave', true),
    };
}
