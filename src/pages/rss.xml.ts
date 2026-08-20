import rss from '@astrojs/rss';
import { getPublishedPosts } from '../utils/posts';
import type { APIContext } from 'astro';

export async function GET(context: APIContext) {
  const posts = await getPublishedPosts();
  return rss({
    title: 'Cybersecurity Research Notebook',
    description: 'Technical notes on Windows internals, kernel driver analysis, reverse engineering, and debugging.',
    site: context.site || new URL('http://localhost:4321'),
    items: posts.map((post) => ({
      title: post.data.title,
      pubDate: post.data.date,
      description: post.data.description,
      link: `/research/${post.slug}/`,
    })),
  });
}
