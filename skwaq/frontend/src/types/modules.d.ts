// Type declarations for modules without their own types

declare module 'react-markdown' {
  import React from 'react';
  
  interface ReactMarkdownProps {
    children: string;
    remarkPlugins?: any[];
    components?: Record<string, React.ComponentType<any>>;
  }
  
  const ReactMarkdown: React.FC<ReactMarkdownProps>;
  export default ReactMarkdown;
}

declare module 'remark-gfm' {
  const remarkGfm: any;
  export default remarkGfm;
}

declare module 'react-syntax-highlighter/dist/esm/styles/prism' {
  export const tomorrow: any;
}

declare module 'react-syntax-highlighter' {
  interface SyntaxHighlighterProps {
    style?: any;
    language?: string;
    PreTag?: string;
    children: string;
    showLineNumbers?: boolean;
    [key: string]: any;
  }
  
  export const Prism: React.FC<SyntaxHighlighterProps>;
}

declare module 'file-saver' {
  export function saveAs(data: Blob | File | string, filename?: string, options?: { type?: string }): void;
}