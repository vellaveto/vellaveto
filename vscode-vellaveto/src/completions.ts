import * as vscode from 'vscode';

/** Policy field names and their descriptions for TOML completions. */
const POLICY_FIELDS: Array<{ label: string; detail: string; insertText: string }> = [
    { label: 'name', detail: 'Policy display name (required)', insertText: 'name = "${1:my-policy}"' },
    { label: 'tool_pattern', detail: 'Glob pattern for tool names (required)', insertText: 'tool_pattern = "${1:*}"' },
    { label: 'function_pattern', detail: 'Glob pattern for function names', insertText: 'function_pattern = "${1:*}"' },
    { label: 'priority', detail: 'Evaluation priority (higher = checked first)', insertText: 'priority = ${1:100}' },
    { label: 'id', detail: 'Unique policy identifier', insertText: 'id = "${1:namespace:tool:rule}"' },
    { label: 'policy_type', detail: 'Policy type: Allow, Deny, or Conditional', insertText: 'policy_type = "${1|Allow,Deny|}"' },
];

const SECTION_COMPLETIONS: Array<{ label: string; detail: string; insertText: string }> = [
    { label: '[[policies]]', detail: 'Add a new policy rule', insertText: '[[policies]]\nname = "${1:policy-name}"\ntool_pattern = "${2:*}"\nfunction_pattern = "${3:*}"\npriority = ${4:100}\nid = "${5:ns:tool:rule}"\npolicy_type = "${6|Allow,Deny|}"' },
    { label: '[policies.path_rules]', detail: 'Path-based access rules', insertText: '[policies.path_rules]\nallowed_globs = [${1:}]\nblocked_globs = [${2:}]' },
    { label: '[policies.network_rules]', detail: 'Network/domain access rules', insertText: '[policies.network_rules]\nallowed_domains = [${1:}]\nblocked_domains = [${2:}]' },
    { label: '[policies.network_rules.ip_rules]', detail: 'IP-based access rules', insertText: '[policies.network_rules.ip_rules]\nblock_private = ${1|true,false|}' },
    { label: '[policies.policy_type.Conditional.conditions]', detail: 'Conditional policy rules', insertText: '[policies.policy_type.Conditional.conditions]\non_no_match = "${1|continue,deny,allow|}"\nparameter_constraints = [\n  { param = "${2:*}", op = "${3|glob,regex|}", pattern = "${4:pattern}", on_match = "${5|deny,require_approval,allow|}", on_missing = "skip" },\n]' },
    { label: '[injection]', detail: 'Injection detection settings', insertText: '[injection]\nenabled = ${1|true,false|}\nblocking = ${2|true,false|}' },
    { label: '[dlp]', detail: 'DLP scanning settings', insertText: '[dlp]\nenabled = ${1|true,false|}\nblocking = ${2|true,false|}\nscan_responses = ${3|true,false|}' },
    { label: '[audit]', detail: 'Audit logging settings', insertText: '[audit]\nredaction_level = "${1|KeysAndPatterns,High,None|}"' },
];

const ENUM_VALUES: Record<string, string[]> = {
    policy_type: ['Allow', 'Deny'],
    on_no_match: ['continue', 'deny', 'allow'],
    on_match: ['deny', 'allow', 'require_approval'],
    on_missing: ['skip', 'deny', 'allow'],
    op: ['glob', 'regex'],
    redaction_level: ['None', 'KeysAndPatterns', 'High'],
};

/**
 * Creates a TOML completion provider for Vellaveto policy files.
 */
export function createCompletionProvider(): vscode.CompletionItemProvider {
    return {
        provideCompletionItems(
            document: vscode.TextDocument,
            position: vscode.Position,
        ): vscode.CompletionItem[] {
            const lineText = document.lineAt(position).text;
            const linePrefix = lineText.substring(0, position.character);
            const items: vscode.CompletionItem[] = [];

            // Detect if we're at the start of a line (section/field completions)
            if (linePrefix.trim() === '' || linePrefix.trim().startsWith('[')) {
                // Offer section completions
                for (const sec of SECTION_COMPLETIONS) {
                    const item = new vscode.CompletionItem(
                        sec.label,
                        vscode.CompletionItemKind.Module,
                    );
                    item.detail = sec.detail;
                    item.insertText = new vscode.SnippetString(sec.insertText);
                    items.push(item);
                }
            }

            // Offer field completions if inside a [[policies]] block
            if (isInPolicyBlock(document, position)) {
                for (const field of POLICY_FIELDS) {
                    const item = new vscode.CompletionItem(
                        field.label,
                        vscode.CompletionItemKind.Property,
                    );
                    item.detail = field.detail;
                    item.insertText = new vscode.SnippetString(field.insertText);
                    items.push(item);
                }
            }

            // Offer enum value completions after =
            const eqMatch = linePrefix.match(/(\w+)\s*=\s*"?$/);
            if (eqMatch) {
                const key = eqMatch[1];
                const values = ENUM_VALUES[key];
                if (values) {
                    for (const val of values) {
                        const item = new vscode.CompletionItem(
                            val,
                            vscode.CompletionItemKind.EnumMember,
                        );
                        item.detail = `${key} value`;
                        items.push(item);
                    }
                }
            }

            return items;
        },
    };
}

function isInPolicyBlock(document: vscode.TextDocument, position: vscode.Position): boolean {
    for (let i = position.line; i >= 0; i--) {
        const line = document.lineAt(i).text.trim();
        if (line === '[[policies]]') return true;
        if (line.startsWith('[') && !line.startsWith('[[policies]]') && !line.startsWith('[policies.')) {
            return false;
        }
    }
    return false;
}
