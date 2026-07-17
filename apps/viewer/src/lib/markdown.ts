import { marked, Renderer, type Tokens } from 'marked';

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character] ?? character);
}

function safeHref(href: string): string | null {
  const trimmed = href.trim();
  if (trimmed.startsWith('#') || trimmed.startsWith('/') || trimmed.startsWith('./') || trimmed.startsWith('../')) {
    return trimmed;
  }
  try {
    const url = new URL(trimmed);
    return ['http:', 'https:', 'mailto:'].includes(url.protocol) ? trimmed : null;
  } catch {
    return null;
  }
}

class AssistantRenderer extends Renderer {
  override html({ text }: Tokens.HTML | Tokens.Tag): string {
    return escapeHtml(text);
  }

  override link({ href, title, tokens }: Tokens.Link): string {
    const label = this.parser.parseInline(tokens);
    const safe = safeHref(href);
    if (!safe) return label;
    const titleAttribute = title ? ` title="${escapeHtml(title)}"` : '';
    return `<a href="${escapeHtml(safe)}" target="_blank" rel="noreferrer noopener"${titleAttribute}>${label}</a>`;
  }

  override image({ text }: Tokens.Image): string {
    return `<span class="markdown-image-label">[Image: ${escapeHtml(text || 'attachment')}]</span>`;
  }
}

export function renderAssistantMarkdown(source: string): string {
  return marked.parse(source, {
    gfm: true,
    breaks: true,
    async: false,
    renderer: new AssistantRenderer()
  });
}
