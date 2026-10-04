import fs from 'node:fs';
import path from 'node:path';
import { SnapshotError } from './workspace.js';

// Resolves symlinks of every existing path component, appending a nonexistent
// tail lexically, so aliased paths compare by their real on-disk location even
// when the leaf itself does not exist yet (its real parent is still resolved).
// A dangling symlink is followed to its lexical target as well, so a link that
// aliases a file which has not been created is not mistaken for a distinct
// location.
export function realLocation(target) {
  let current = path.resolve(target);
  const tail = [];
  const resolvedLinks = new Set();
  for (;;) {
    try {
      const real = fs.realpathSync(current);
      return tail.length === 0 ? real : path.join(real, ...tail.reverse());
    } catch (error) {
      if (error.code === 'ELOOP') {
        throw new SnapshotError('IO_ERROR', `cannot resolve ${target}: cyclic symbolic link`);
      }
      if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') {
        throw new SnapshotError('IO_ERROR', `cannot resolve ${target}: ${error.message}`);
      }
      let linkStats = null;
      try {
        linkStats = fs.lstatSync(current);
      } catch {
        // The component itself is absent, not a dangling link.
      }
      if (linkStats?.isSymbolicLink()) {
        if (resolvedLinks.has(current)) {
          throw new SnapshotError('IO_ERROR', `cannot resolve ${target}: cyclic symbolic link`);
        }
        resolvedLinks.add(current);
        let destination;
        try {
          destination = fs.readlinkSync(current);
        } catch (readlinkError) {
          throw new SnapshotError('IO_ERROR', `cannot resolve ${target}: ${readlinkError.message}`);
        }
        current = path.resolve(path.dirname(current), destination);
        continue;
      }
      tail.push(path.basename(current));
      const parent = path.dirname(current);
      if (parent === current) return current;
      current = parent;
    }
  }
}
