# Feature Specification: Person Search

**Feature Branch**: `002-person-search`
**Created**: 2026-11-12
**Status**: Draft
**Input**: User description: "Busca de uma pessoa específica nas câmeras por foto de referência, com cadastro de alvo, ranking por similaridade e varredura ao vivo opcional"
**Decisions**: `docs/decisions/2026-11-12-busca-pessoa-especifica.md` (D47 to D67)

**Scope boundary**: the rules of decision D1 apply unchanged. Every frame this feature reads
comes from the operator lab or from a target with written authorization, and the live pass
carries the strictest reach gate the project has (D59). This feature adds no new way to
reach a network: it reads stored data, and the optional live pass follows the same gate as
the credential check.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Give a photo and get the appearances (Priority: P1)

The operator has a photo of a person, runs the search, and gets a ranked list of every
place that person appears in the stored frames: which camera, at what time, the frame file,
and how close the match is. The photo becomes a named target in the database, so the next
search on that person needs no photo.

**Why this priority**: this is the request. Everything else in this feature supports it.
The pipeline today can group anonymous faces, but it cannot answer "where did this person
appear".

**Independent Test**: register one target from one photo against a database that holds the
same person in two frames of two cameras, then read the ranking back and confirm both
appearances are listed with their camera, time, frame path and score, and that a second run
adds no duplicate hit.

**Acceptance Scenarios**:

1. **Given** a photo with a detectable face and a stored frame of that same person, **When**
   the search runs, **Then** that appearance is listed with camera, time, frame path and
   score.
2. **Given** a target already registered, **When** the search runs by target identifier,
   **Then** no photo is needed and the same ranking comes back.
3. **Given** the same search run twice, **When** the second run finishes, **Then** the number
   of stored hits is unchanged.
4. **Given** a photo with no detectable face, **When** the search runs, **Then** no target is
   created and the command exits with a failure that names the reason.
5. **Given** a target registered with three photos of the same person, **When** the search
   runs, **Then** each appearance carries the score of the closest of the three photos.

---

### User Story 2 - The target gets a name in the report (Priority: P2)

When a target matches a person already grouped by the pipeline, that person shows the target
name in the report, unless the operator already gave the person a name. The face report
states, for every person, whether it matches a target and which one.

**Why this priority**: it is what turns a score list into something readable at a glance, and
it attaches the name where the operator already looks. It depends on the target existing.

**Independent Test**: label one person by hand, let a different target match it, and confirm
the manual label survives; then let a target match an unlabeled person and confirm the
target name appears in both reports.

**Acceptance Scenarios**:

1. **Given** an unlabeled person that matches a target, **When** the search runs, **Then** the
   person carries the target name.
2. **Given** a person labeled by hand and a target that matches it, **When** the search runs,
   **Then** the manual label is unchanged.
3. **Given** the face report, **When** it prints a person that matches a target, **Then** the
   line says which target and which score.

---

### User Story 3 - Look at the cameras now, on request (Priority: P3)

The operator asks for the same search against the live cameras, and the tool captures,
detects and compares before answering. Nothing reaches a camera unless this was asked for
explicitly.

**Why this priority**: it answers the present instead of the history, which is useful, but
it costs network time per camera and writes frames of everyone in view, so it ranks below
the stored search.

**Independent Test**: run the search without the live option and confirm no network call is
made; run it with the live option against one lab camera showing the target and confirm the
new appearance is in the answer and in the next stored search.

**Acceptance Scenarios**:

1. **Given** a search without the live option, **When** it runs, **Then** no camera is
   contacted.
2. **Given** a search with the live option and a lab camera showing the target, **When** it
   finishes, **Then** the appearance is listed and stored.
3. **Given** a stored camera address outside the declared target list, **When** the live
   search starts, **Then** it stops before any packet leaves and names the address.

---

### User Story 4 - Undo a wrong registration (Priority: P4)

The operator removes a target registered by mistake. The target, its photos and its hits are
gone; no frame, no face and no stored embedding is touched.

**Why this priority**: it is the smallest slice, but a registration that cannot be undone is
not acceptable, and it is the only exception this feature makes to keeping everything.

**Independent Test**: register a target, run the search, remove the target, then confirm the
target, its photos and its hits are absent and the faces, frames and persons are all still
there.

**Acceptance Scenarios**:

1. **Given** a registered target with hits, **When** the removal runs, **Then** the target, its
   photos and its hits are gone.
2. **Given** the removal of a target that wrote its name into a person, **When** it finishes,
   **Then** that name is cleared from the person.
3. **Given** a person labeled by hand with a different name, **When** a target is removed,
   **Then** the manual label is unchanged.

---

### Edge Cases

- A reference photo that holds two faces, or holds no face at all.
- A reference photo file that is missing or unreadable.
- The same photo passed twice in one registration.
- A target name that differs only by case or by surrounding spaces.
- A target that matches one person and, later, a merge joins that person with another.
- Two different targets that both match the same person.
- A stored frame whose file is missing on disk.
- A stored face whose embedding has an unexpected length.
- A live pass interrupted midway.
- A search with no target and no photo, on a database with no targets.
- A database with zero stored faces.
- The match threshold left at the unmeasured value.

## Requirements *(mandatory)*

### Functional Requirements

**The target**

- **FR-001**: Users MUST be able to register a target by passing one or more reference
  photos and a name, in one command.
- **FR-002**: The target name MUST be required, trimmed and unique. A repeat with the same
  name MUST add photos to the existing target and MUST NOT create a second target.
- **FR-003**: A target MUST accept several photos, and a comparison against it MUST use the
  highest similarity among its photos.
- **FR-004**: The reference photo file MUST be kept on disk with its path stored, like every
  other frame.
- **FR-005**: A reference photo with no detectable face, or a file that cannot be read, MUST
  fail the command, name the reason, and create no target.

**The search**

- **FR-006**: Users MUST be able to search by reference photo and by an already registered
  target.
- **FR-007**: The search MUST compare the target against every stored face and return a
  ranked list of appearances, each with the person, the camera, the time, the frame path and
  the score.
- **FR-008**: The search MUST accept a camera filter and a time window, the same ones the
  existing appearance search accepts.
- **FR-009**: A search with no photo and no target MUST search every registered target.
- **FR-010**: A search for a target that does not exist MUST fail with a reason.
- **FR-011**: The match threshold MUST come from its own configuration key, separate from
  the grouping threshold, and MUST be labelled unmeasured until the lab measures it.

**The stored hits**

- **FR-012**: Each match MUST be stored once per target and face, with its score, and a
  repeated search MUST NOT create a duplicate row.
- **FR-013**: A stored hit MUST never be deleted by a later search.
- **FR-014**: A target that matches a person with no label MUST write the target name into
  that person label.
- **FR-015**: A person label that the operator set by hand MUST never be overwritten by a
  target.
- **FR-016**: The face report MUST state, for each person that matches a target, which
  target and which score.

**The live pass**

- **FR-017**: The live pass MUST run only when explicitly requested, and MUST be off by
  default.
- **FR-018**: The live pass MUST reuse the existing capture, detection, storage and grouping
  path of the face scan, and MUST record a run like every other scan.
- **FR-019**: Before the live pass sends any packet, every camera in the run MUST be checked
  against the declared target list, and one address outside that list MUST stop the whole
  run with the address named.
- **FR-020**: The live pass MUST reach only cameras already stored, never an address that
  was not found by a previous authorized scan.

**Removal**

- **FR-021**: Users MUST be able to remove a target by identifier, which removes the target,
  its photos and its hits.
- **FR-022**: The removal MUST clear the person label only where it equals the target name,
  and MUST NOT touch any frame, face or embedding.

**Reach and hygiene**

- **FR-023**: Every command of this feature MUST record the target set it reached, as the
  existing scans do.
- **FR-024**: No credential, photo path of a person and no biometric value MUST appear in a
  log line at any level.
- **FR-025**: The command surface MUST keep one verb for searching: a search group with one
  command for targets and one for the existing appearance search, and the documented
  contract MUST state both.
- **FR-026**: The schema changes of this feature MUST be applied by a versioned migration
  with a rollback path.
- **FR-027**: The feature MUST ship with tests that fail when the logic breaks, including the
  duplicate hit case, the manual label case and the reach gate case, plus a real run with the
  raw output recorded.

### Key Entities

- **Target**: a person the operator wants to find, identified by a required unique name and
  by the reference photos registered for it. It is data the operator created, not something
  the pipeline inferred.
- **Target photo**: one reference image of a target, kept on disk with its path and its
  stored representation, used for comparison.
- **Target hit**: the record that a target matched one detected face in one stored frame,
  with the score of that match and when it was first stored.
- **Person**: the existing cluster of faces. This feature can write a name into it, only when
  it has none, and never overwrites a name a person already carries.
- **Face and frame**: the existing detected face and stored frame. This feature reads them
  and never deletes them.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A person present in stored frames is found by one command from one photo, with
  each appearance carrying camera, time, frame path and score.
- **SC-002**: Running the same search twice leaves the stored hit count identical.
- **SC-003**: Zero reference photos with no detectable face produce a target.
- **SC-004**: Zero manual person labels are changed by a target match.
- **SC-005**: A search without the live option makes zero network calls, visible in the log
  of the run.
- **SC-006**: Removing a target leaves zero rows of that target and zero changes to frames,
  faces and embeddings.
- **SC-007**: A live pass with one camera outside the declared list sends zero packets naming
  that address, and the run output names the address.
- **SC-008**: The match threshold in the configuration is labelled unmeasured until the lab
  pair set produces a value, and the report does not present it as measured.
- **SC-009**: Every command of this feature has a pasted raw output from a real run.

## Assumptions

- The database is the dedicated instance created by the previous feature, and it already
  holds cameras, frames and faces. This feature adds tables and reads the existing ones.
- The number of stored faces is lab scale, so a linear comparison is acceptable and no
  vector index is introduced. The cost is recorded as a risk, not hidden.
- The existing face model and metric are reused: the same embedding and the same cosine
  comparison over the normalized vector.
- The existing grouping threshold keeps its meaning. The new threshold is a second value
  with a second meaning, and neither replaces the other.
- The operator runs the commands by hand, on the local workstation. There is no scheduler,
  no server and no notification.
- A target name is the identity key. Two people with the same name cannot be two targets in
  this batch.
- The reference photo directory lives under the configured frame root.

### Out of scope for this batch

- Any alert, notification or watch loop when a target appears.
- Any web or API surface: the answer is a command.
- A vector index or any new dependency for speeding up the comparison.
- Merging two targets that turn out to be the same person.
- Removing a hit without removing its target.
- Retention, encryption or access control for the reference photos.
- Automatic labeling beyond writing the target name into an empty person label.
- Any change to how cameras are found or how frames are captured.
