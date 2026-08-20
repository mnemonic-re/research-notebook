import rss from '@astrojs/rss';
import { getPublishedPosts } from '../utils/posts';
import type { APIContext } from 'astro';

export async function GET(context: APIContext) {
  const posts = await getPublishedPosts();
  const site = context.site || new URL('https://mnemonic-re.github.io/research-notebook/');
  const base = import.meta.env.BASE_URL.endsWith('/') ? import.meta.env.BASE_URL : `${import.meta.env.BASE_URL}/`;

  return rss({
    title: 'Cybersecurity Research Notebook',
    description: 'Technical notes on Windows internals, kernel driver analysis, reverse engineering, and debugging.',
    site: site,
    items: posts.map((post) => ({
      title: post.data.title,
      pubDate: post.data.date,
      description: post.data.description,
      link: `${base}research/${post.slug}/`,
    })),
  });
}
