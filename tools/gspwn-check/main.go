// gspwn-check parses and compiles a directory of syzlang description files
// against pkg/compiler. It loads real per-file .const sidecars the same way
// sys/syz-sysgen does, so the semantic checker runs to completion instead of
// stopping at the type-check-only pass a nil consts map produces.
//
// tools/syzlang_gen.py builds this file with `go build <file>` from a
// syzkaller checkout and reads the exit code and the stdout verdict line, so
// neither an exit code nor a message changes without changing that caller and
// .github/workflows/syzlang.yml with it. main_test.go pins both.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/sys/targets"
)

// Exit codes. 2 marks a caller error and 1 a rejected description set, which
// is the distinction syzlang_gen.py's cmd_compile reads.
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

// run carries every exit path and every message the binary has, and takes the
// argument vector and both streams from its caller so a test observes them.
// It returns the code main exits with.
//
// The paths are: a flag parse failure and -h, both from the flag package; an
// absent -dir; a parse failure; an arch with no registered linux target; a
// const sidecar that fails to load; a compile failure; and success.
func run(argv []string, stdout, stderr io.Writer) int {
	name, args := "gspwn-check", []string(nil)
	if len(argv) > 0 {
		name, args = argv[0], argv[1:]
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "directory of .txt description files")
	arch := fs.String("arch", "amd64", "target arch, matches .const file arch tags")
	// The imported syzkaller packages register flags of their own on
	// flag.CommandLine from init, -vv among them. Copying those keeps the
	// flag set this binary accepts, and the usage text it prints, what the
	// global set gave before the parse moved off it.
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if fs.Lookup(f.Name) == nil {
			fs.Var(f.Value, f.Name, f.Usage)
		}
	})
	if err := fs.Parse(args); err != nil {
		// Parse has already written the error and the usage text to stderr.
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *dir == "" {
		fmt.Fprintln(stderr, "usage: gspwn-check -dir <path> [-arch amd64]")
		return exitUsage
	}
	errCount := 0
	eh := func(pos ast.Pos, msg string) {
		errCount++
		fmt.Fprintf(stderr, "%v: %v\n", pos, msg)
	}
	desc := ast.ParseGlob(*dir+"/*.txt", eh)
	if desc == nil {
		fmt.Fprintln(stderr, "parse: failed, see errors above")
		return exitFail
	}
	target := targets.Get(targets.Linux, *arch)
	if target == nil {
		fmt.Fprintf(stderr, "no linux/%s target registered\n", *arch)
		return exitFail
	}
	matches, _ := filepath.Glob(*dir + "/*.txt.const")
	var constFile *compiler.ConstFile
	if len(matches) == 0 {
		constFile = compiler.NewConstFile()
	} else {
		constFile = compiler.DeserializeConstFile(*dir+"/*.txt.const", eh)
	}
	if errCount > 0 {
		fmt.Fprintf(stderr, "const load: failed, %d error(s)\n", errCount)
		return exitFail
	}
	consts := constFile.Arch(*arch)
	prog := compiler.Compile(desc, consts, target, eh)
	if prog == nil || errCount > 0 {
		fmt.Fprintf(stderr, "compile: failed, %d error(s)\n", errCount)
		return exitFail
	}
	fmt.Fprintf(stdout, "compile: OK, %d const(s) loaded, %d syscall(s), %d resource(s), "+
		"%d type(s), %d unsupported\n",
		len(consts), len(prog.Syscalls), len(prog.Resources), len(prog.Types),
		len(prog.Unsupported))
	return exitOK
}
