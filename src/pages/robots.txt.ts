import type { APIContext } from 'astro';

export async function GET(context: APIContext) {
  const siteUrl = context.site ? context.site.href : 'http://localhost:4321/';
  const sitemapUrl = new URL('sitemap-index.xml', siteUrl).href;

  const robotsTxt = `User-agent: *
Allow: /

Sitemap: ${sitemapUrl}
`;

  return new Response(robotsTxt, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
    },
  });
}
