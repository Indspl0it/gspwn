// gspwn-check parses and compiles a directory of syzlang description files
// against pkg/compiler. It loads real per-file .const sidecars the same way
// sys/syz-sysgen does, so the semantic checker runs to completion instead of
// stopping at the type-check-only pass a nil consts map produces.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/sys/targets"
)

func main() {
	dir := flag.String("dir", "", "directory of .txt description files")
	arch := flag.String("arch", "amd64", "target arch, matches .const file arch tags")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: gspwn-check -dir <path> [-arch amd64]")
		os.Exit(2)
	}
	errCount := 0
	eh := func(pos ast.Pos, msg string) {
		errCount++
		fmt.Fprintf(os.Stderr, "%v: %v\n", pos, msg)
	}
	desc := ast.ParseGlob(*dir+"/*.txt", eh)
	if desc == nil {
		fmt.Fprintln(os.Stderr, "parse: failed, see errors above")
		os.Exit(1)
	}
	target := targets.Get(targets.Linux, *arch)
	if target == nil {
		fmt.Fprintf(os.Stderr, "no linux/%s target registered\n", *arch)
		os.Exit(1)
	}
	matches, _ := filepath.Glob(*dir + "/*.txt.const")
	var constFile *compiler.ConstFile
	if len(matches) == 0 {
		constFile = compiler.NewConstFile()
	} else {
		constFile = compiler.DeserializeConstFile(*dir+"/*.txt.const", eh)
	}
	if errCount > 0 {
		fmt.Fprintf(os.Stderr, "const load: failed, %d error(s)\n", errCount)
		os.Exit(1)
	}
	consts := constFile.Arch(*arch)
	prog := compiler.Compile(desc, consts, target, eh)
	if prog == nil || errCount > 0 {
		fmt.Fprintf(os.Stderr, "compile: failed, %d error(s)\n", errCount)
		os.Exit(1)
	}
	fmt.Printf("compile: OK, %d const(s) loaded, %d syscall(s), %d resource(s), "+
		"%d type(s), %d unsupported\n",
		len(consts), len(prog.Syscalls), len(prog.Resources), len(prog.Types),
		len(prog.Unsupported))
}
