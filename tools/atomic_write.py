#!/usr/bin/env python3
"""One durable write path for the generators that emit committed artefacts.

Five generators used to carry their own `write_json`. They disagreed on three
things that matter to this tree.

  fsync            `ctrl_rank` flushed the file to the disk and the others
                   returned once the bytes reached the page cache, so a crash
                   after a successful run could lose an artefact the next
                   phase reads.
  temporary name   all five wrote `<path>.tmp`, one fixed name per target, so
                   two runs against one output directory overwrite each
                   other's temporary file and one of them renames bytes the
                   other wrote.
  newline          `ctrl_surface` opened its temporary with the platform
                   default, so a regeneration on Windows wrote CRLF into a
                   tree whose artefacts are LF. Commit e6b045d records that
                   happening.

None of the five fsynced the containing directory, so a crash after the rename
could leave the directory entry pointing at the previous file on ext4 and on
xfs.

`atomic_write_text` fixes all four for a single file. `StagedWriteSet` extends
the same handling to a run that emits several artefacts read as one set.

Guarantee for a single file
---------------------------

The bytes reach a temporary file in the target's own directory, the file is
fsynced, `os.replace` moves it onto the target, and the directory is fsynced.
`os.replace` is atomic on POSIX and on NTFS, so a concurrent reader observes
either the previous file or the new one and never a truncated file. A failure
at any point before the rename leaves the target untouched, and the temporary
is removed on every failure path.

Guarantee for a set, and what it excludes
-----------------------------------------

`StagedWriteSet.stage` writes and fsyncs one temporary per file and changes no
target. `commit` then issues one `os.replace` per staged file. A failure during
staging therefore leaves every target as it was.

The set is not atomic across files. No filesystem available here renames
several paths in one transaction, and this module does not claim one. A failure
between two renames leaves the earlier targets replaced and the later ones
unchanged. What the staging buys is the width of that window: the exposure
falls from the whole serialisation and write of every file to the interval
between consecutive renames, and every temporary still staged when the failure
lands is removed. A caller that needs a true all-or-nothing group across files
needs a different mechanism, such as a single archive or a directory swap.

File mode
---------

`tempfile.mkstemp` creates a file readable by its owner alone. Where the target
already exists its mode is copied onto the temporary before the rename, so a
regeneration preserves the artefact's permissions; where it does not,
`DEFAULT_FILE_MODE` applies.
"""
import errno
import logging
import os
import stat
import tempfile

logger = logging.getLogger("atomic_write")

DEFAULT_FILE_MODE = 0o644

# Directory fsync needs a read handle on the directory itself, which Windows
# refuses. The rename is still atomic there; only the durability of the
# directory entry across a power loss is unavailable.
_CAN_FSYNC_DIRECTORY = os.name == "posix"


def _target_mode(path):
    """The mode to give the replacement: the target's own where it exists."""
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError as e:
        if e.errno not in (errno.ENOENT, errno.ENOTDIR):
            raise
        return DEFAULT_FILE_MODE


def _fsync_directory(directory):
    """Flush the directory entry so a completed rename survives a power loss."""
    if not _CAN_FSYNC_DIRECTORY:
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _discard(tmp_path):
    """Remove a temporary, reporting a removal that itself fails."""
    try:
        os.unlink(tmp_path)
    except OSError as e:
        if e.errno != errno.ENOENT:
            logger.warning("cannot remove temporary file %s: %s", tmp_path, e)


def _stage_file(path, text):
    """Write `text` to a fsynced temporary beside `path` and return its name.

    The caller owns the temporary from here: it renames it onto the target or
    discards it. Every failure inside this function removes the temporary
    before raising, so a raise leaves nothing behind.
    """
    if not isinstance(text, str):
        raise TypeError("atomic_write takes text, not %s, for %s"
                        % (type(text).__name__, path))
    target = os.path.abspath(path)
    directory = os.path.dirname(target)
    if not directory:
        raise ValueError("cannot resolve an output directory for %r" % (path,))

    # mkstemp names the temporary uniquely, so two runs against one directory
    # no longer share <path>.tmp and no longer rename each other's bytes.
    fd, tmp = tempfile.mkstemp(dir=directory,
                               prefix=os.path.basename(target) + ".",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, _target_mode(target))
    except BaseException:
        _discard(tmp)
        raise
    return tmp


def atomic_write_text(path, text):
    """Replace `path` with `text` durably, in UTF-8, with LF line endings.

    Raises OSError where the directory is unwritable or the write fails, and
    TypeError where `text` is not a string. The target is unchanged on every
    raise.
    """
    target = os.path.abspath(path)
    directory = os.path.dirname(target)
    tmp = _stage_file(target, text)
    try:
        os.replace(tmp, target)
    except BaseException:
        _discard(tmp)
        raise
    _fsync_directory(directory)
    logger.debug("wrote %s (%d bytes)", target, len(text))
    return target


class StagedWriteSet(object):
    """Several files staged together and renamed onto their targets together.

    Read the module docstring for what the grouping does and does not
    guarantee. Used as a context manager, an exception on the way out
    discards every temporary that has not been committed.

        with StagedWriteSet() as staged:
            staged.stage(map_path, map_text)
            staged.stage(inventory_path, inventory_text)
            staged.commit()
    """

    def __init__(self):
        # Ordered: commit renames in the order the caller staged, so a
        # partial commit is a prefix of a known sequence and not a set.
        self._pending = []
        self._committed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.abort()
        return False

    @property
    def pending(self):
        """The targets staged and not yet renamed, in staging order."""
        return [target for target, _ in self._pending]

    def stage(self, path, text):
        """Write one file's bytes to a fsynced temporary. No target changes.

        A raise here discards every temporary staged so far, so a caller that
        abandons the set part way leaves nothing behind.
        """
        if self._committed:
            raise RuntimeError("cannot stage %s onto a committed write set"
                               % (path,))
        target = os.path.abspath(path)
        if target in self.pending:
            raise ValueError("%s is staged twice in one write set" % (target,))
        try:
            tmp = _stage_file(target, text)
        except BaseException:
            self.abort()
            raise
        self._pending.append((target, tmp))
        return target

    def commit(self):
        """Rename every staged file onto its target, then fsync each directory.

        On a failure part way the targets already renamed keep their new
        content, every temporary not yet renamed is discarded, and the
        original error propagates. The renamed prefix is named in the log so
        an operator knows which artefacts moved.
        """
        if self._committed:
            raise RuntimeError("this write set is already committed")
        renamed = []
        while self._pending:
            target, tmp = self._pending[0]
            try:
                os.replace(tmp, target)
            except BaseException:
                logger.error("commit failed at %s after replacing %d of %d "
                             "file(s): %s", target, len(renamed),
                             len(renamed) + len(self._pending),
                             ", ".join(renamed) or "none")
                self.abort()
                raise
            self._pending.pop(0)
            renamed.append(target)
        self._committed = True
        for directory in sorted({os.path.dirname(t) for t in renamed}):
            _fsync_directory(directory)
        logger.debug("committed %d file(s): %s", len(renamed),
                     ", ".join(renamed))
        return renamed

    def abort(self):
        """Discard every staged temporary. Targets are left as they are."""
        discarded = [tmp for _, tmp in self._pending]
        self._pending = []
        for tmp in discarded:
            _discard(tmp)
        if discarded:
            logger.info("discarded %d staged temporary file(s)",
                        len(discarded))
        return len(discarded)
