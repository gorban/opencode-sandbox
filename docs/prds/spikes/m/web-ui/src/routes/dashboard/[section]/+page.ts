import { error } from '@sveltejs/kit';

export function load({ params }: { params: { section: string } }) {
  if (!['projects', 'sandboxes', 'threads'].includes(params.section)) error(404, 'Unknown view');
  return { section: params.section };
}
