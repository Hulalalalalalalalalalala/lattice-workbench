import { snapshotFromDocuments, normalizeSnapshot } from './workspace.js';

function compareCodePoints(a, b) {
  const left = Array.from(a, (char) => char.codePointAt(0));
  const right = Array.from(b, (char) => char.codePointAt(0));
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}

function sameTags(a, b) {
  return a.length === b.length && a.every((tag, i) => tag === b[i]);
}

// Merges one field of one document across the base/current/incoming fork.
// Returns `{ value, conflict }`: a conflict means both sides changed the field
// to different normalized values. A change by only one side, or identical
// changes on both sides, is accepted.
function mergeField(name, baseValue, currentValue, incomingValue) {
  const same = name === 'tags'
    ? (a, b) => sameTags(a, b)
    : (a, b) => a === b;
  const currentChanged = !same(currentValue, baseValue);
  const incomingChanged = !same(incomingValue, baseValue);
  if (currentChanged && incomingChanged && !same(currentValue, incomingValue)) {
    return { value: currentValue, conflict: true };
  }
  if (incomingChanged) return { value: incomingValue, conflict: false };
  return { value: currentValue, conflict: false };
}

// Three-way merge of an offline-edited `incoming` snapshot against the edit
// `base` snapshot, preserving non-conflicting online changes in `current`.
// Bodies compare (and are kept) as whole strings; tags compare as one
// normalized group. Returns `{ snapshot, changedIds, conflicts }`, where
// `changedIds` lists the documents that differ from `current` after the merge.
export function reconcileSnapshots(currentData, baseData, incomingData) {
  const current = normalizeSnapshot(currentData);
  const base = normalizeSnapshot(baseData);
  const incoming = normalizeSnapshot(incomingData);
  const byId = (documents) => new Map(documents.map((document) => [document.id, document]));
  const currentMap = byId(current);
  const baseMap = byId(base);
  const incomingMap = byId(incoming);

  const conflicts = new Map();
  const addConflict = (id, field) => {
    if (!conflicts.has(id)) conflicts.set(id, new Set());
    conflicts.get(id).add(field);
  };

  const merged = new Map();

  for (const id of new Set([...currentMap.keys(), ...baseMap.keys(), ...incomingMap.keys()])) {
    const inCurrent = currentMap.has(id);
    const inBase = baseMap.has(id);
    const inIncoming = incomingMap.has(id);
    const baseDoc = baseMap.get(id);
    const currentDoc = currentMap.get(id);
    const incomingDoc = incomingMap.get(id);

    // Both sides add a brand-new id: accept only when the normalized documents
    // are identical; otherwise the add itself conflicts.
    if (!inBase) {
      if (inCurrent && inIncoming) {
        const identical = currentDoc.title === incomingDoc.title
          && currentDoc.body === incomingDoc.body
          && sameTags(currentDoc.tags, incomingDoc.tags);
        if (identical) {
          merged.set(id, structuredClone(currentDoc));
        } else {
          addConflict(id, 'document');
          // Keep the current side's document so title-uniqueness collection
          // stays based on the live state.
          merged.set(id, structuredClone(currentDoc));
        }
      } else if (inCurrent) {
        merged.set(id, structuredClone(currentDoc));
      } else {
        merged.set(id, structuredClone(incomingDoc));
      }
      continue;
    }

    // The document existed at the base. If either side deleted it: both sides
    // deleting deletes; one side deleting while the other left it untouched
    // also deletes; a delete meeting a modification conflicts and keeps the
    // surviving side.
    if (!inCurrent || !inIncoming) {
      if (!inCurrent && !inIncoming) {
        continue;
      }
      const surviving = inCurrent ? currentDoc : incomingDoc;
      if (!baseEqual(baseDoc, surviving)) {
        addConflict(id, 'document');
        merged.set(id, structuredClone(surviving));
      }
      continue;
    }

    // The document is alive on all three sides: merge field by field, so
    // changes to different fields are both kept.
    const fields = {};
    for (const name of ['title', 'body', 'tags']) {
      const result = mergeField(name, baseDoc[name], currentDoc[name], incomingDoc[name]);
      fields[name] = result.value;
      if (result.conflict) addConflict(id, name);
    }
    merged.set(id, {
      id,
      title: fields.title,
      body: fields.body,
      tags: structuredClone(fields.tags),
    });
  }

  // Field and add/delete conflicts suppress the title-duplicate report; only
  // when none exist do we check that the final titles are unique (title swaps
  // resolve naturally because every kept title is counted once per owner).
  if (conflicts.size === 0) {
    const owners = new Map();
    for (const document of merged.values()) {
      const owner = owners.get(document.title);
      if (owner === undefined) {
        owners.set(document.title, document.id);
      } else {
        addConflict(document.id, 'title');
        addConflict(owner, 'title');
      }
    }
  }

  const changedIds = [];
  for (const [id, document] of merged) {
    const existing = currentMap.get(id);
    if (!existing
      || existing.title !== document.title
      || existing.body !== document.body
      || !sameTags(existing.tags, document.tags)) {
      changedIds.push(id);
    }
  }
  for (const id of currentMap.keys()) {
    if (!merged.has(id)) changedIds.push(id);
  }
  changedIds.sort(compareCodePoints);

  const snapshot = snapshotFromDocuments(merged.values());
  return {
    snapshot,
    changedIds,
    conflicts: [...conflicts.entries()]
      .map(([id, fields]) => ({ id, fields: [...fields].sort(compareCodePoints) }))
      .sort((a, b) => compareCodePoints(a.id, b.id)),
  };
}

function baseEqual(baseDoc, document) {
  return baseDoc.title === document.title
    && baseDoc.body === document.body
    && sameTags(baseDoc.tags, document.tags);
}
