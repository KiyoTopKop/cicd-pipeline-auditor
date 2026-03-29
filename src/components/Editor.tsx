import { useRef, useEffect } from 'react';
import MonacoEditor, { useMonaco, Monaco } from '@monaco-editor/react';
import type { Finding } from '../engine/types';

interface EditorProps {
  value: string;
  onChange: (value: string | undefined) => void;
  findings: Finding[];
  selectedFindingId: string | null;
  onSelectFinding: (id: string | null) => void;
}

export function Editor({ value, onChange, findings, selectedFindingId }: EditorProps) {
  const monaco = useMonaco();
  const editorRef = useRef<any>(null);
  const decorationsRef = useRef<string[]>([]);

  const handleEditorDidMount = (editor: any, monacoInstance: Monaco) => {
    editorRef.current = editor;

    // Premium Obsidian Theme for Monaco
    monacoInstance.editor.defineTheme('pipelint-premium', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'comment', foreground: '404354', fontStyle: 'italic' },
        { token: 'string', foreground: 'C3E88D' },
        { token: 'keyword', foreground: '89DDFF' },
        { token: 'number', foreground: 'F78C6C' },
        { token: 'type', foreground: 'FFCB6B' },
        { token: 'operator', foreground: '89DDFF' },
      ],
      colors: {
        'editor.background': '#05060B00', // Transparent to show glass-panel background
        'editor.foreground': '#E1E1E6',
        'editorLineNumber.foreground': '#2C2E3A',
        'editorLineNumber.activeForeground': '#00F2FF',
        'editorIndentGuide.background': '#1A1C2E',
        'editorIndentGuide.activeBackground': '#2C2E3A',
        'editorGutter.background': '#05060B00',
        'editor.selectionBackground': '#00F2FF22',
        'editor.lineHighlightBackground': '#FFFFFF05',
        'editorCursor.foreground': '#00F2FF',
      }
    });
    
    monacoInstance.editor.setTheme('pipelint-premium');
  };

  useEffect(() => {
    if (!monaco || !editorRef.current) return;

    const editor = editorRef.current;
    
    // Severity to Monaco marker severity
    const markerSeverityMap: Record<string, number> = {
      CRITICAL: monaco.MarkerSeverity.Error,
      HIGH: monaco.MarkerSeverity.Warning,
      MEDIUM: monaco.MarkerSeverity.Info,
      LOW: monaco.MarkerSeverity.Hint,
    };

    const markers = findings
      .filter(f => f.line !== undefined)
      .map(f => ({
        severity: markerSeverityMap[f.severity] || monaco.MarkerSeverity.Info,
        message: `${f.ruleId}: ${f.message}`,
        startLineNumber: f.line!,
        startColumn: 1,
        endLineNumber: f.line!,
        endColumn: 1000,
      }));

    const model = editor.getModel();
    if (model) {
      monaco.editor.setModelMarkers(model, 'pipelint', markers);
    }

    const newDecorations: any[] = [];
    
    findings.forEach(f => {
      if (f.line === undefined) return;
      
      const isSelected = f.id === selectedFindingId;
      if (isSelected) {
        newDecorations.push({
          range: new monaco.Range(f.line, 1, f.line, 1),
          options: {
            isWholeLine: true,
            className: 'selected-finding-line',
            linesDecorationsClassName: `gutter-icon-${f.severity.toLowerCase()}`,
          }
        });

        editor.revealLineInCenter(f.line, monaco.editor.ScrollType.Smooth);
      }
    });

    decorationsRef.current = editor.deltaDecorations(decorationsRef.current, newDecorations);

  }, [monaco, findings, selectedFindingId]);

  return (
    <div className="editor-wrapper">
        <MonacoEditor
            height="100%"
            language="yaml"
            theme="pipelint-premium"
            value={value}
            onChange={onChange}
            onMount={handleEditorDidMount}
            options={{
                minimap: { enabled: false },
                fontSize: 13,
                fontFamily: "'Geist Mono', monospace",
                lineHeight: 22,
                scrollBeyondLastLine: false,
                wordWrap: 'on',
                renderWhitespace: 'none',
                guides: { indentation: true },
                padding: { top: 16, bottom: 16 },
                smoothScrolling: true,
                cursorBlinking: 'smooth',
                cursorSmoothCaretAnimation: 'on',
                mouseWheelZoom: true,
                stickyScroll: { enabled: false },
            }}
        />
        <style>{`
          .selected-finding-line {
            background-color: rgba(0, 242, 255, 0.05) !important;
            border-left: 2px solid var(--accent-cyan);
            box-shadow: inset 10px 0 20px rgba(0, 242, 255, 0.03);
          }
          .gutter-icon-critical { border-left: 3px solid var(--critical); }
          .gutter-icon-high { border-left: 3px solid var(--high); }
          .gutter-icon-medium { border-left: 3px solid var(--medium); }
          .gutter-icon-low { border-left: 3px solid var(--low); }
        `}</style>
    </div>
  );
}
