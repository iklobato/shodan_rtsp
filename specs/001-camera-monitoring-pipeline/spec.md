# Feature Specification: Camera Monitoring Pipeline

**Feature Branch**: `001-camera-monitoring-pipeline`
**Created**: 2026-11-11
**Status**: Draft
**Input**: User description: "Turn shodan_rtsp into a production ready camera monitoring pipeline: schema with migrations, brand fingerprinting, read-only CVE exploitation for frames, and face clustering"

**Scope boundary**: this batch is for the operator lab and for targets with written
authorization (decision D1). Any other network is out of scope, and every new
network path added by this batch must name the target set it can reach.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A database that remembers history (Priority: P1)

The operator runs a scan and every camera seen, every scan, every observation and
every finding is stored with real relationships between them. The schema is created
and changed by versioned migrations instead of by hand, and the status of a camera
says which path produced the frame, not just that it is reachable.

**Why this priority**: the other four fronts all write to this schema. Nothing else
in the batch has anywhere to put data until this lands. Today three loose tables
exist with no foreign keys between them, and the schema was created by hand.

**Independent Test**: point the tool at an empty database, apply migrations from
zero, run one scan against one lab camera on one port, then read the camera, the
scan and the observation rows back through the query path.

**Acceptance Scenarios**:

1. **Given** an empty database, **When** migrations run from zero, **Then** the full
   schema exists, and a second run makes no further change.
2. **Given** a scan of one lab camera on one port, **When** it finishes, **Then** one
   camera row, one scan row and one observation row for that port exist and are linked.
3. **Given** a camera that answered on RTSP but needed a CVE path to give a frame,
   **When** the frame arrives, **Then** its status says the CVE path produced it and
   does not report it as offline.
4. **Given** a schema change, **When** the migration is applied, **Then** a rollback
   path exists and reads are not blocked for the whole migration.

---

### User Story 2 - Identify the camera make and model (Priority: P2)

From the stored banner and the service scan, the tool says what the device is
(vendor, product, version), keeps the raw evidence it based that on, and attaches
the known vulnerable version range when the product appears in the CVE map. A new
brand is a data line, not a code change.

**Why this priority**: identification is the input to the CVE front. Without it the
tool knows an address answers on port 554 and nothing more, so no CVE can be
selected and no frame can be obtained through one.

**Independent Test**: feed a stored banner of a known camera and a device that
matches no signature, then check that the first reports vendor, product and version
with its raw evidence kept, and the second reports unknown while still keeping the
raw banner.

**Acceptance Scenarios**:

1. **Given** a stored banner for a known camera, **When** fingerprinting runs,
   **Then** vendor, product and version are reported and the raw banner fields are kept.
2. **Given** a product that appears in the CVE map, **When** fingerprinting runs,
   **Then** the vulnerable version range is attached to that camera.
3. **Given** a device that matches no signature, **When** fingerprinting runs,
   **Then** the result says unknown and the raw banner is still stored.
4. **Given** a new brand added as a data line only, **When** fingerprinting runs,
   **Then** that brand is detected with no code change.

---

### User Story 3 - Obtain a frame through a known CVE, read only (Priority: P3)

When a camera cannot be read over normal RTSP, the tool tries the CVE classes in
this batch (authentication bypass and fixed firmware credentials, unauthenticated
read of a snapshot or file, unauthenticated ONVIF), takes at most one frame as
proof, writes nothing to the target, and records the candidate with the failure
reason when no frame comes back.

**Why this priority**: this is what turns identification into a picture, which is
what the face front needs. It ranks below the two fronts above it because it needs
both of them.

**Independent Test**: run the CVE path against a lab camera with a known vulnerable
firmware, confirm exactly one frame is stored, confirm the device state is unchanged,
then run it against a device that is not vulnerable and confirm a recorded reason
instead of an error.

**Acceptance Scenarios**:

1. **Given** a lab camera with known vulnerable firmware, **When** the CVE path runs,
   **Then** exactly one frame is stored and nothing is written to the device.
2. **Given** a match where one class yields no frame, **When** the path finishes,
   **Then** the other classes are tried and the failure reason is recorded.
3. **Given** a device that is not vulnerable, **When** the path runs, **Then** there
   is no frame and a recorded reason, and no crash.
4. **Given** the ONVIF class succeeds, **Then** model and firmware are recorded too.

---

### User Story 4 - Faces grouped into people, and the monitoring answer (Priority: P4)

Frames are scanned for faces, each face is compared against the faces already known,
a face never seen before creates a person, a face that matches joins the person it
matched, and when one face matches two people those two are merged. People are
anonymous by default with an optional manual label. The operator then asks one
question, who appeared, where and when, and gets the answer from stored data.

**Why this priority**: this is the point of the batch, and it is last because it
needs frames from the fronts above it. It ranks with the monitoring answer because
the person entity is what makes that answer possible.

**Independent Test**: scan a frame holding one face never seen before, then a second
frame with the same face, then a frame that matches two existing people, and check
that one person is created, no second person appears, and the two clusters end as one.

**Acceptance Scenarios**:

1. **Given** a frame with one face never seen before, **When** the scan runs,
   **Then** one person is created and the face is linked to it.
2. **Given** the same person in a second frame, **When** the scan runs, **Then** no
   new person is created.
3. **Given** two people that both match one new face, **When** the scan runs,
   **Then** the two are merged into one person.
4. **Given** the operator asks who appeared where and when, **When** the query runs,
   **Then** the answer names the person, the camera and the time, with no SQL
   written by hand.
5. **Given** the match threshold, **When** the lab has measured it on known pairs,
   **Then** the configured value is the measured one, and any other value is
   labelled a placeholder.

---

### User Story 5 - A code base the other fronts can be trusted on (Priority: P5)

Dead code, an unreachable branch, a credential written to the log, an unused helper
that mutates its input, an entire retired proxy path and stale docs are removed, and
the credential check tries the brand specific set before the generic one.

**Why this priority**: it carries the least user value, but it is the front that
makes the others reviewable: the proxy path alone accounts for about twenty of the
thirty five existing tests and a config section the lab scope cannot use.

**Independent Test**: run the linter and the test suite before and after, and confirm
the suite still passes with the direct path covered and the retired tests gone.

**Acceptance Scenarios**:

1. **Given** the current test suite, **When** the retired proxy path is removed,
   **Then** the remaining suite passes and the direct path is still covered.
2. **Given** a scan that logs at the default level, **When** credentials are used,
   **Then** no credential value appears in any log line.
3. **Given** the credential check, **When** a brand is known, **Then** the brand
   specific credentials are tried before the generic set.
4. **Given** a module that nothing imports and no test references, **When** the cleanup
   runs, **Then** it is gone from the tree, unless a later front of this batch revives it
   as a declared deliverable. `scanners/brand_probe.py` is that exception: front 3 rewrites
   it to read `brands.yaml`, so the cleanup removes the dead pattern tables inside it
   instead of the file.

---

### Edge Cases

- An empty database, or a scan that finds zero cameras.
- A port that accepts a connection but never sends a decodable frame.
- A stored banner that is truncated or carries no product field.
- Two cameras on the same address on different ports.
- A face in a frame that is too small or too blurred to compare.
- The same person appearing twice in one frame.
- A frame row whose file is missing on disk.
- Disk full while writing a frame file.
- A CVE path that hangs, and a scan interrupted midway.
- A brand with a credential set configured and a brand with none.
- Shodan returning nothing for a private range, which is expected and not an error.
- A migration applied while a scan is writing.

## Requirements *(mandatory)*

### Functional Requirements

**Scope and safety**

- **FR-001**: Every scan MUST be restricted to the operator lab or to targets with
  written authorization, and every new network path MUST state which target set it
  can reach.
- **FR-002**: Each scan run MUST record the target set it reached, so the run can be
  told apart from a run against a different range.
- **FR-003**: CVE modules MUST NOT write to, persist on, or alter the target, and
  MUST take at most one frame as proof.

**Storage and schema**

- **FR-004**: The schema MUST be created and changed by versioned migrations that can
  run from zero on an empty database and can be rolled back.
- **FR-005**: Cameras, scan runs, observations, CVE findings, faces, face frames and
  people MUST be stored as separate entities with relationships between them.
- **FR-006**: The system MUST store one observation row per camera per port per scan.
- **FR-007**: A camera MUST carry a status that states which path produced its frame:
  unknown, responded, stream obtained, frame by CVE, or offline.
- **FR-008**: Frames MUST be stored as files on disk with the path held in the
  database, not as encoded payload inside a database column.
- **FR-009**: Frames and face embeddings MUST be kept indefinitely; no code in this
  batch deletes stored frames or embeddings.

**Identification**

- **FR-010**: The system MUST keep the raw banner fields it based an identification
  on, alongside the interpreted vendor, product and version.
- **FR-011**: The service scan MUST cover RTSP and the web and ONVIF ports of the
  batch, so a camera that exposes no RTSP is still found.
- **FR-012**: Brand detection MUST be driven by signature data, so a new brand is a
  data line and not a code change.
- **FR-013**: When a product appears in the CVE map, the matching vulnerable version
  range MUST be attached to the camera.
- **FR-014**: A device that matches no signature MUST be recorded as unknown, and its
  raw banner MUST still be stored.
- **FR-015**: The credential check MUST try the brand specific credential set before
  the generic set.

**CVE exploitation**

- **FR-016**: The batch MUST cover three CVE classes: authentication bypass and fixed
  firmware credentials, unauthenticated read of a snapshot or file, and
  unauthenticated ONVIF.
- **FR-017**: When one class yields no frame, the remaining classes MUST be tried
  before the attempt is abandoned.
- **FR-018**: A candidate MUST be recorded with its failure reason when no frame comes
  back, so a match without a picture is still visible.
- **FR-019**: A successful ONVIF read MUST also record the model and the firmware.
- **FR-020**: Every network step of a CVE attempt MUST time out rather than hang.

**Faces and people**

- **FR-021**: Every stored frame MUST be scanned for faces, and each detected face
  MUST be compared against the faces already known.
- **FR-022**: A face never seen before MUST create a person; a face that matches MUST
  join the person it matched.
- **FR-023**: When one face matches two people, those two MUST be merged into one.
- **FR-024**: People MUST be anonymous by default, with an optional manual label.
- **FR-025**: The face match threshold MUST come from configuration, and any value
  used before the lab measurement MUST be labelled a placeholder.

**Reading the data**

- **FR-026**: The command surface MUST be organized as subcommands, covering a
  network scan, a credential check, a CVE scan, a face scan, a face report and a
  search.
- **FR-027**: The search MUST answer who appeared, where and when, reading from the
  stored data.
- **FR-028**: The face report MUST state, for each result, which path produced the
  frame.
- **FR-029**: The CVE match MUST be read from stored observations, not recomputed
  from the service scan output on each run.

**Hygiene**

- **FR-030**: No credential value MUST appear in any log line at any level.
- **FR-031**: The retired proxy path and its configuration MUST be removed.
- **FR-032**: Dead code and unreachable branches MUST be removed, and the
  documentation MUST reflect the new command surface.
- **FR-033**: Each capability in this batch MUST ship with a test that fails when the
  logic breaks, plus a real run in the lab with the raw output recorded.
- **FR-034**: No dependency, framework or build tooling MUST be added without an
  explicit decision.

### Key Entities

- **Camera**: a device at an address and port. Carries the identified vendor,
  product and version, the raw evidence for that identification, and a status that
  names the path that produced its frame.
- **Scan run**: one execution of one scan kind against one target set, with the time
  and the target set it reached.
- **Camera observation**: what one camera looked like at one port in one scan run.
  One row per camera per port per scan. This is what makes change over time visible.
- **CVE finding**: a vulnerable product and version range matched to a camera, with
  the class tried, the outcome, and the failure reason when there is no frame.
- **Face**: one detected face in one frame, with its embedding.
- **Face frame**: the stored frame, its file path, and which camera and scan produced it.
- **Person**: a cluster of faces judged to be the same individual. Anonymous by
  default, with an optional manual label.
- **Brand signature**: the data that maps a banner pattern to a brand, held as
  configuration data rather than code.
- **Credential set**: the credentials tried per brand, brand specific before generic.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A fresh empty database reaches the full schema in one step, and running
  the same step again changes nothing.
- **SC-002**: After one scan of the lab, the number of observation rows equals the
  number of cameras found multiplied by the number of ports scanned, with no row lost.
- **SC-003**: Every stored camera reports a vendor, product and version or an explicit
  unknown, and zero raw banners are lost in the process.
- **SC-004**: The lab camera with known vulnerable firmware yields a frame through the
  CVE path, and the device state after the attempt is identical to the state before.
- **SC-005**: A person who appears in two separate frames is stored as one person, not
  two.
- **SC-006**: The question of who appeared where and when is answered by one command,
  with no SQL written by hand.
- **SC-007**: Zero credential values appear in any log line at any level.
- **SC-008**: The test suite passes after the retired proxy tests are removed, and the
  direct read path is still covered by a test that can fail.
- **SC-009**: Every front in this batch has a pasted raw output from a real lab run.
- **SC-010**: The match threshold in the configuration is the value measured in the
  lab; before that measurement, every appearance of a threshold is marked placeholder.

## Assumptions

- The lab is a media server plus a virtual machine running a known vulnerable camera
  firmware, on an isolated network with no route out.
- The dedicated database is the one already defined in the repository compose file on
  its own port. The current database holds no rows, so there is no data to migrate and
  the first migration is generated from scratch.
- The Shodan mode is kept but is only useful for a public range owned by the operator.
  Shodan does not index private space, so it cannot serve the lab.
- The credential check is kept, with brand specific credentials tried first.
- The service scan excludes the addresses of the local machine.
- Names are normalized during the schema work: the camera table gets its full name, and
  the encoded image column becomes a path column.
- The credential log line and the unused helper that mutates its input are removed.
- The stored confidence value becomes a number rather than text.
- The documentation is rewritten for the new subcommands, because the current one
  documents the flat flags this batch replaces.

### Out of scope for this batch

- Deployment, containers for the application, scheduling, metrics and alerting.
- Encryption, access control and audit for stored frames and embeddings.
- A backup policy for the frame directory.
- Retention periods and any purge: retention is unlimited by decision.
- Any automatic watchlist: people stay anonymous unless the operator labels one.
- Whether the person label gets its own command, a view or plain SQL.
- Continuous integration: the only gate is running the linter and the test suite by hand.
- Rotating the stored credentials.
