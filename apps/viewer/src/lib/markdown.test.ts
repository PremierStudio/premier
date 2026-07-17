import { describe, expect, it } from 'vitest';
import { renderAssistantMarkdown } from './markdown';

describe('renderAssistantMarkdown', () => {
  it('renders the structured Markdown used by trace copilots', () => {
    const html = renderAssistantMarkdown([
      '## Highest-impact issue',
      '',
      '**The reviewer returned no evidence.**',
      '',
      '- No model call',
      '- No tool execution',
      '',
      '`correlation_id` was empty.',
      '',
      '```sh',
      'premier inspect trace-1',
      '```'
    ].join('\n'));

    expect(html).toContain('<h2>Highest-impact issue</h2>');
    expect(html).toContain('<strong>The reviewer returned no evidence.</strong>');
    expect(html).toContain('<ul>');
    expect(html).toContain('<code>correlation_id</code>');
    expect(html).toContain('<pre><code class="language-sh">premier inspect trace-1');
  });

  it('escapes raw HTML and refuses unsafe or embedded resources', () => {
    const html = renderAssistantMarkdown([
      '<script>alert("trace")</script>',
      '[unsafe](javascript:alert(1))',
      '![tracking](https://example.com/pixel.gif)',
      '[safe](https://premier.dev/docs)'
    ].join('\n\n'));

    expect(html).not.toContain('<script>');
    expect(html).not.toContain('javascript:');
    expect(html).not.toContain('<img');
    expect(html).toContain('href="https://premier.dev/docs"');
    expect(html).toContain('rel="noreferrer noopener"');
  });
});
