import { getCollection, type CollectionEntry } from 'astro:content';

/**
 * Single source of truth for publicly published research posts.
 * Strictly excludes any post where draft === true.
 * Returns posts sorted by publication date descending (newest first).
 */
export async function getPublishedPosts(): Promise<CollectionEntry<'posts'>[]> {
  const posts = await getCollection('posts', ({ data }) => data.draft !== true);
  return posts.sort((a, b) => b.data.date.valueOf() - a.data.date.valueOf());
}
