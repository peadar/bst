bst(1) "bst" "Bestie"

# NAME

bst - run executables in their own spacetime.

# SYNOPSIS

bst [options] [--] [executable [args...]]

# DESCRIPTION

Runs _executable_ in its own isolated environment.  If _executable_ is not
specified, then _${SHELL:-/bin/sh}_ is run.
The meaning of isolated depends on the platform or the version of bst, but bst
generally tries to unshare every available namespace and arrange the inner
environment to be as deterministic as possible within these parameters.

Because of the relativistic nature of these isolated environments with
regard to the executable being run, we call these environments "spacetimes".
Spacetimes may define their own meaning about devices, randomness, locale,
time, namespaces, and filesystem structure.

Users of bst may choose to opt-out of some of the isolation.

# OPTIONS

\--argv0 <string>
	Run _executable_ with the specified value for _argv[0]_.
	By default, _argv[0]_ is _executable_ itself.

\--share-<ns>[=<file>]
	Share the specified namespaces with the namespace anchored by
	*<file>*, which can be a file like /proc/[pid]/ns/mnt,
	or a bind-mount of that file, or a file created by
	_bst --persist=_*<dir>*.  If no *=<file>* is given, then share the
	given namespace with the process invoking bst.

	Available namespaces are:
	- *cgroup* (since Linux 4.6)
	- *ipc* (since Linux 2.6.19)
	- *mnt*
	- *net* (since Linux 2.6.24)
	- *pid* (since Linux 3.8)
	- *time* (since Linux 5.6)
	- *uts* (since Linux 2.6.19)
	- *user* (since Linux 3.8)

	All namespaces are unshared by default; _e.g.,_ if _--share-mnt_
	is not given, then the child process runs in a new (unshared)
	mount namespace intialized as a copy of bst's parent's mount
	namespace.

\--persist <dir>
	Persist all namespaces of the new process into files in the
	given directory, allowing re-entry via _--share-\*=<dir>_ even after bst
	exits (but note that pid namespaces whose init died cannot be re-entered).

	The files are named the same as the namespace files in /proc/[pid]/ns.
	This option is equivalent to bind-mounting /proc/[pid]/ns/\* into
	*<dir>*/\* after invoking bst, except avoiding a race where the child
	exits before the bind-mounts complete.  Note that in order to persist the
	mount namespace, the persist directory must be on a private mount subtree
	(for more information, see *mount_namespaces*(7)).

	See *bst-unpersist*(1) for more details about how to release persisted
	namespace files.

\--workdir <dir>
	Change the current work directory for the inner process to *<dir>*.

	*<dir>* must be an absolute path relative to the current root, or, if
	a new root has been specified with _--root_, the new root.

\--root <dir>
	Change the root directory for the inner process to *<dir>*.

\--mount [source=]<source>,[target=]<target>,[type=]<type>,<options...>
	Perform a mount in the inner process' mount namespace.

	*<target>* must be an absolute path relative to the current root, or, if
	a new root has been specified with _--root_, the new root.

	*<source>* can be a path relative to the initial work directory, or an
	absolute path relative to the inner root directory.

	*<type>* is the filesystem type, or _none_ if ignored.
	Consult _/proc/filesystems_ for a list of supported filesystem types.

	Additionally, the following filesystem types are recognized by *bst*:
	- *bst_devtmpfs* (see _--no-fake-devtmpfs_)

	*<options>* are mount options. Recognized options are the same as with
	*mount*(1).

	You cannot use this option with _--share=mount_.

\--mutable <dir>
	Make *<dir>* mutable. This is useful for making specific subtrees writeable
	when the parent directory has been mounted read-only.

	*<dir>* must be an absolute path relative to the current root, or, if
	a new root has been specified with _--root_, the new root.

	Any changes to the contents of *<dir>* are discarded when the inner process
	and all of its descendants exits.

	You cannot use this option with _--share=mount_.

\--uid <uid>
	Set the user ID of the inner process to *<uid>*.

\--gid <gid>
	Set the group ID of the inner process to *<gid>*.

\--groups <gid>[,gid]...
	Set the additional group IDs of the inner process to the specified GIDs.

\--arch <name>
	Set the execution domain of the inner process to the specified architecture.
	This affects the output of _uname -m_, and takes the same architecture names
	as *setarch*(1).

\--hostname <hostname>
	Set the hostname for the inner process' UTS namespace.

	By default, if the UTS namespace is unshared, *bst* sets the hostname to
	_"localhost"_.

	You cannot use this option with _--share=uts_.

\--domainname <domainname>
	Set the domain name for the inner process' UTS namespace.

	By default, if the UTS namespace is unshared, *bst* sets the domain name to
	_"localdomain"_.

	You cannot use this option with _--share=uts_.

\--time <name-or-id>=<seconds>[.<nanoseconds>]
	Set the value of the specified clock for the inner process' time namespace.

	Valid clock names are the same as the ones described in *time_namespaces*(7).
	Alternatively, the numerical clock IDs can be supplied.

	You cannot use this option with _--share=time_.

\--init <argv>
	Set the init process to be used as parent of *<executable>*. *<argv>* is
	a space-delimited argv array, and _argv[0]_ must be an absolute path to a
	valid executable in the current filesystem root (in other words, the init
	executable does not need to exist in the root specified by _--root_).

	If an empty *<argv>* is passed to _--init_, no init process will be
	spawed by bst, and *<executable>* will be executed directly.

	If bst unshares the pid namespace and no _--init_ is specified, it uses
	by default *bst-init*(1).

\--no-fake-devtmpfs
	Do not replace devtmpfs mounts with a fake devtmpfs.

	By default, *bst* constructs the contents of a fake devtmpfs with a minimal
	set of devices and symlinks. In particular, because devtmpfses cannot be
	mounted in user namespaces, this allows programs wishing to run in a user
	namespace yet still have access to non-problematic devices like _/dev/null_
	to pass in _--mount dev,/dev,devtmpfs_ and have this work out of the box.

\--no-derandomize
	Do not try to reduce sources of randomness.

	By default, *bst* tries to run inner processes in a somewhat more deterministic
	environment. So far, it does so by symlinking _/dev/random_ and _/dev/urandom_ to
	_/dev/zero_, and by disabling ASLR for the inner process.

\--no-proc-remount
	Do not remount the existing _/proc_ mount if in a mount and pid namespace.

	By default, *bst* automatically tries to mount a new procfs on top of _/proc_
	if it detects it to be on another filesystem than _/_.

\--no-loopback-setup
	Do not bring up the _lo_ interface.

	By default, *bst* automatically brings up _lo_ and adds the address
	127.0.0.1/8 to it when in a network namespace.

	This does nothing when used with _--share=net_.

# SEE ALSO

*bst-unpersist*(1), *bst-init*(1), *namespaces*(7), *mount*(1), *setarch*(1)
