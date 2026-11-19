package projectlane

// Outcomes of a bind and the exit status each is reported with. The statuses
// stay clear of safe's own (0/10-17/20-22/100-104/127): they are safe-core's,
// and the gate maps them.
const (
	BindSchema = 1

	OutcomePublished          = "published"
	OutcomeRefused            = "refused"
	OutcomeInstallFailed      = "install_failed"
	OutcomeVerificationFailed = "verification_failed"
	OutcomeInputsChanged      = "inputs_changed"
	OutcomeInterrupted        = "interrupted"
	OutcomePublicationFailed  = "publication_failed"

	ExitPublished          = 0
	ExitRefused            = 30
	ExitInstallFailed      = 31
	ExitVerificationFailed = 32
	ExitInputsChanged      = 33
	ExitInterrupted        = 34
	ExitPublicationFailed  = 35
)

// Reasons a bind is refused, or fails. Stable identifiers.
const (
	ReasonLockNotHeld          = "lock_not_held"
	ReasonLockBusy             = "lock_held_by_another"
	ReasonLockFailed           = "lock_operation_failed"
	ReasonProjectInvalid       = "project_invalid"
	ReasonTreeRootSymlink      = "tree_root_symlink"
	ReasonTreeRootInvalid      = "tree_root_invalid"
	ReasonInputUnsafe          = "input_unsafe"
	ReasonRequestInvalid       = "request_invalid"
	ReasonCompetingLockfile    = "competing_lockfile"
	ReasonLockfileUnreadable   = "lockfile_unreadable"
	ReasonLinksNotSupported    = "links_not_supported"
	ReasonLockfilePathsOutside = "lockfile_path_outside_tree"
	ReasonFlagsInconsistent    = "lockfile_flags_inconsistent"
	ReasonStagingFailed        = "staging_failed"
	ReasonStateDirInvalid      = "state_dir_invalid"
	ReasonPlatformUnsupported  = "platform_unsupported"
	ReasonStartFailed          = "install_start_failed"
	ReasonInstallExit          = "install_exit"
	ReasonInstallSignaled      = "install_signaled"
	ReasonProcessesRemain      = "install_processes_remain"
	ReasonVerification         = "verification_failed"
	ReasonInputsChanged        = "inputs_changed"
	ReasonSignal               = "signal"
	ReasonPublication          = "publication_error"
)
