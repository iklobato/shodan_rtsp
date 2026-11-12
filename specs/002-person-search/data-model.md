# Data Model: Person Search

**Feature**: `specs/002-person-search/spec.md`
**Plan**: `specs/002-person-search/plan.md`
**Decisions**: `docs/decisions/2026-11-12-busca-pessoa-especifica.md` (D49, D53, D55, D57, D62, D64)
**Created**: 2026-11-12

Target: PostgreSQL 16 on the dedicated instance (D4, D40). Three new tables, applied by one
Alembic revision, `0003_person_search`, with a downgrade that drops them in dependency
order. The existing seven tables are read and never altered.

Table names stay singular, as the previous feature settled (`camera`, `face`, `person`).

## Entity overview

```text
target 1---n target_photo
target 1---n target_hit n---1 face  n---1 face_frame n---1 camera
face   n---1 person
```

A target is operator-created data. A hit joins it to a face the pipeline detected. Nothing
in this model deletes a `face`, a `face_frame` or an embedding.

## target

One person the operator wants to find, identified by a name.

| Column | Type | Null | Notes |
|--------|------|------|-------|
| id | integer PK | no | |
| name | varchar(128) | no | required, trimmed, unique (D55) |
| created_at | timestamptz | no | |
| updated_at | timestamptz | no | |

Constraints and indexes:

- `UNIQUE (name)`: the name is the identity key, so a repeated registration with the same
  name adds photos to this row instead of creating a second target (FR-002).
- `CHECK (name <> '')` after trimming: an empty name would make the target unreachable by
  the key that identifies it.

Validation, at construction and not only at the database:

- `name` is trimmed, non-empty, and at most 128 characters. A name that differs only by
  surrounding spaces is the same name.
- Case is preserved as typed and compared case-sensitively, as the existing `person.label`
  does. The spec records name normalization beyond trimming as undecided.

## target_photo

One reference image of one target.

| Column | Type | Null | Notes |
|--------|------|------|-------|
| id | integer PK | no | |
| target_id | integer FK target(id) | no | |
| path | varchar(512) | no | path on disk, relative to the configured frame root (D62) |
| embedding | same as `face.embedding` | no | 512 raw values, unnormalized (D44) |
| created_at | timestamptz | no | |

Constraints and indexes:

- `INDEX (target_id)`: the photos of one target, which is the comparison input.
- `UNIQUE (path)`: one row per file, so a re-run does not point two rows at one file.
- `CHECK (array_length(embedding, 1) = 512)`, PostgreSQL only, through the same
  `EMBEDDING` type and the same dialect guard `models/face.py:31-40` already uses.
- `path` is never empty. A row whose file is missing on disk is reportable, not a reason to
  drop the row: the row is the record that the photo was registered.

## target_hit

The record that one target matched one detected face.

| Column | Type | Null | Notes |
|--------|------|------|-------|
| id | integer PK | no | |
| target_id | integer FK target(id) | no | |
| face_id | integer FK face(id) | no | |
| score | double precision | no | cosine similarity of the match, -1 to 1 |
| created_at | timestamptz | no | when the hit was first stored |

Constraints and indexes:

- `UNIQUE (target_id, face_id)`: one hit per target and face (FR-012). A repeated search
  updates the score and never adds a row.
- `INDEX (face_id)`: given a face, which targets it matches. This is the join the
  `report faces` line uses.
- `INDEX (target_id)`: the ranking of one target.
- `CHECK (score >= -1 AND score <= 1)`: the metric is cosine over unit vectors, so a value
  outside that range is a bug and not data.

Update rule: on a repeated search the score is raised only when the new value is higher.
A hit is never deleted by a search (FR-013).

## Deletion rule

`search person --forget N` deletes, inside one transaction:

1. every `target_hit` with that `target_id`;
2. every `target_photo` with that `target_id`, and the file each row names;
3. the `target` row;
4. the `person.label` values that are exactly the target name become null (D64).

It touches no `face`, no `face_frame`, no embedding of a face, and no other `person` column.
A file that is already missing on disk is not an error: the row is the record, and the
removal completes.

## Why no column on face or person

A face can match several targets, so a single `target_id` column on `face` would be a lie.
A person can match several targets for the same reason. The join table `target_hit` is the
only shape that keeps both facts, and it is also what makes the ranking a query instead of a
recomputation.

## Indexes that serve the two read paths

The ranking walks `target` to `target_hit` to `face` to `face_frame` to `camera`:

1. `target (name)` finds the target by the key the operator uses.
2. `target_photo (target_id)` reads the comparison input.
3. `target_hit (target_id, score)` orders the ranking.
4. `face (frame_id)` reaches the frame of each face.
5. `face_frame (camera_id, captured_at)` orders by time and reaches the camera.

The `report faces` line walks `person` to `face` to `target_hit`:

1. `face (person_id)` selects the faces of the person.
2. `target_hit (face_id)` resolves which targets match, with the score.

No index is added that these two paths do not use.
