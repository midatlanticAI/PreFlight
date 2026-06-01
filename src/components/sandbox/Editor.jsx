// src/components/sandbox/Editor.jsx
//
// CodeMirror 6 wrapper. Lives only on the sandbox route, so it's lazy-loaded
// through App.jsx's lazyNamed and never enters any other chunk. The editor
// owns its document state after mount; React drives the seed value via
// `initialValue` and receives changes via `onChange`.
//
// Why the two-ref pattern: CodeMirror should be created once, not on every
// React render, so we keep mount in a single useEffect keyed on `initialValue`
// (a new seed value resets the buffer on purpose, e.g. when a parent loads a
// saved snippet). `onChangeRef` lets the parent swap its onChange handler
// across renders without tearing the editor down.

import { useEffect, useRef } from 'react';
import { EditorView, basicSetup } from 'codemirror';
import { javascript } from '@codemirror/lang-javascript';
import { EditorState } from '@codemirror/state';

export function Editor({ initialValue, onChange }) {
  const containerRef = useRef(null);
  const viewRef = useRef(null);
  const onChangeRef = useRef(onChange);

  // Keep the change callback current across parent re-renders without
  // forcing the editor to remount.
  useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return undefined;

    const view = new EditorView({
      state: EditorState.create({
        doc: initialValue,
        extensions: [
          basicSetup,
          javascript({ jsx: true, typescript: true }),
          EditorView.updateListener.of((update) => {
            if (update.docChanged) {
              onChangeRef.current?.(update.state.doc.toString());
            }
          }),
        ],
      }),
      parent: container,
    });
    viewRef.current = view;

    return () => {
      view.destroy();
      viewRef.current = null;
    };
  }, [initialValue]);

  return <div ref={containerRef} data-testid="sandbox-editor" style={{ minHeight: 360 }} />;
}
