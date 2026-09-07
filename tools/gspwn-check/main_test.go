// Tests over run's eight exit paths. The compile gate that ships this binary
// (.github/workflows/syzlang.yml, and tools/syzlang_gen.py compile locally)
// exercises the success path over the committed description set and reads
// nothing else, so the argument handling and the four failure codes are what
// these tests hold.
//
// The package carries no go.mod, because the gate builds it by file path from
// inside a syzkaller checkout and takes pkg/ast, pkg/compiler and sys/targets
// from that checkout's own module. The tests run in the same module context:
//
//	cd <syzkaller checkout>
//	go test -v /path/to/tools/gspwn-check/main.go /path/to/tools/gspwn-check/main_test.go
//
// The checkout is the revision SYZKALLER_REV pins, 1e72964b0111 at the time of
// writing. The figures asserted on the success path are read from
// pkg/compiler at that revision: six syz_builtinN pseudo-syscalls prepended to
// every compile, and the fd resource plus the four the compiler declares
// itself. The type total moves with the revision and is left unasserted.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The three exit codes, written as literals. Asserting against main.go's own
// constants would pass whatever value they held, and the numbers themselves
// are the contract tools/syzlang_gen.py reads.
const (
	wantOK    = 0
	wantFail  = 1
	wantUsage = 2
)

// Two syscalls, one producing the fd resource and one consuming it. A
// description that only declares a resource fails with "unused resource".
const validDesc = `resource fd[int32]: -1
openat$probe(fd const[0xffffffffffffff9c], file ptr[in, string], flags const[0], mode const[0]) fd
ioctl$probe(fd fd, cmd const[0x1234], arg ptr[in, int32])
`

// The syscall numbers validDesc needs. Both are the standard x86-64 ABI
// numbers, the same source tools/syz-stub/gspwn_stub.txt.const names.
const validConst = `arches = amd64
__NR_openat = amd64:257
__NR_ioctl = amd64:16
`

// Pseudo-syscalls carry no __NR_ const, so this pair compiles with no sidecar
// present and reaches the success path through compiler.NewConstFile.
const pseudoDesc = `resource fd[int32]: -1
syz_probe_open(mode const[0]) fd
syz_probe_use(fd fd)
`

var verdictRE = regexp.MustCompile(
	`^compile: OK, (\d+) const\(s\) loaded, (\d+) syscall\(s\), ` +
		`(\d+) resource\(s\), (\d+) type\(s\), (\d+) unsupported\n$`)

// descDir writes each named file into a fresh temporary directory and returns
// its path.
func descDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("writing the fixture %s failed: %v", path, err)
		}
	}
	return dir
}

// call runs the driver with argv[0] fixed, so the usage text the flag package
// prints does not carry the test binary's own path.
func call(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"gspwn-check"}, args...), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestNoDirIsAUsageError(t *testing.T) {
	code, stdout, stderr := call()
	if code != wantUsage {
		t.Errorf("exit code is %d, want %d", code, wantUsage)
	}
	if want := "usage: gspwn-check -dir <path> [-arch amd64]\n"; stderr != want {
		t.Errorf("stderr is %q, want %q", stderr, want)
	}
	if stdout != "" {
		t.Errorf("stdout is %q, want empty", stdout)
	}
}

// An undefined flag reaches the flag package, which writes the error and the
// usage text before Parse returns. The usage text itself is not asserted: the
// test binary registers testing's own -test.* flags on flag.CommandLine and
// run copies every flag it finds there, so under `go test` the printed set is
// larger than the shipped binary's.
func TestUndefinedFlagIsAUsageError(t *testing.T) {
	code, stdout, stderr := call("-nope")
	if code != wantUsage {
		t.Errorf("exit code is %d, want %d", code, wantUsage)
	}
	if want := "flag provided but not defined: -nope"; !strings.Contains(stderr, want) {
		t.Errorf("stderr is %q, want it to contain %q", stderr, want)
	}
	if stdout != "" {
		t.Errorf("stdout is %q, want empty", stdout)
	}
}

// -h prints the usage text and succeeds, which is what flag.ExitOnError did
// before the parse moved to a private flag set.
func TestHelpSucceeds(t *testing.T) {
	code, _, stderr := call("-h")
	if code != wantOK {
		t.Errorf("exit code is %d, want %d", code, wantOK)
	}
	for _, want := range []string{"-dir string", "-arch string"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is %q, want it to contain %q", stderr, want)
		}
	}
}

func TestSyntaxErrorFailsTheParse(t *testing.T) {
	dir := descDir(t, map[string]string{
		"min.txt": "resource fd[int32]: -1\nthis is not syzlang((\n",
	})
	code, stdout, stderr := call("-dir", dir)
	if code != wantFail {
		t.Errorf("exit code is %d, want %d", code, wantFail)
	}
	for _, want := range []string{
		"min.txt:2:6: unexpected identifier",
		"parse: failed, see errors above\n",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is %q, want it to contain %q", stderr, want)
		}
	}
	if stdout != "" {
		t.Errorf("stdout is %q, want empty", stdout)
	}
}

// A directory holding no .txt file fails the same way, from ast.ParseGlob's
// own diagnostic.
func TestEmptyDirFailsTheParse(t *testing.T) {
	dir := descDir(t, nil)
	code, _, stderr := call("-dir", dir)
	if code != wantFail {
		t.Errorf("exit code is %d, want %d", code, wantFail)
	}
	for _, want := range []string{"no files matched by glob", "parse: failed"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is %q, want it to contain %q", stderr, want)
		}
	}
}

// The arch check runs after the parse, so this fixture is a valid one.
func TestUnregisteredArchFails(t *testing.T) {
	dir := descDir(t, map[string]string{
		"min.txt":       validDesc,
		"min.txt.const": validConst,
	})
	code, stdout, stderr := call("-dir", dir, "-arch", "vax")
	if code != wantFail {
		t.Errorf("exit code is %d, want %d", code, wantFail)
	}
	if want := "no linux/vax target registered\n"; stderr != want {
		t.Errorf("stderr is %q, want %q", stderr, want)
	}
	if stdout != "" {
		t.Errorf("stdout is %q, want empty", stdout)
	}
}

// A sidecar line carrying no '=' is rejected by compiler.DeserializeConstFile,
// which reports through the error handler and never reaches the compile.
func TestMalformedConstFileFails(t *testing.T) {
	dir := descDir(t, map[string]string{
		"min.txt":       validDesc,
		"min.txt.const": "arches amd64\n",
	})
	code, stdout, stderr := call("-dir", dir)
	if code != wantFail {
		t.Errorf("exit code is %d, want %d", code, wantFail)
	}
	for _, want := range []string{
		"min.txt.const:1: expect '='",
		"const load: failed, 1 error(s)\n",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is %q, want it to contain %q", stderr, want)
		}
	}
	if stdout != "" {
		t.Errorf("stdout is %q, want empty", stdout)
	}
}

func TestUnknownTypeFailsTheCompile(t *testing.T) {
	broken := strings.Replace(validDesc, "in, int32", "in, nosuchtype", 1)
	if broken == validDesc {
		t.Fatal("the fixture no longer carries the type the test replaces")
	}
	dir := descDir(t, map[string]string{
		"min.txt":       broken,
		"min.txt.const": validConst,
	})
	code, stdout, stderr := call("-dir", dir)
	if code != wantFail {
		t.Errorf("exit code is %d, want %d", code, wantFail)
	}
	for _, want := range []string{
		"unknown type nosuchtype",
		"compile: failed, 1 error(s)\n",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is %q, want it to contain %q", stderr, want)
		}
	}
	if stdout != "" {
		t.Errorf("stdout is %q, want empty", stdout)
	}
}

// With no sidecar the driver builds an empty const file, and a description
// whose syscalls need __NR_ consts then fails the compile with one error per
// syscall. This is the branch tools/syz-stub exists to keep the real gate out
// of.
func TestMissingConstsFailTheCompile(t *testing.T) {
	dir := descDir(t, map[string]string{"min.txt": validDesc})
	code, stdout, stderr := call("-dir", dir)
	if code != wantFail {
		t.Errorf("exit code is %d, want %d", code, wantFail)
	}
	for _, want := range []string{
		"unsupported syscall: openat due to missing const __NR_openat",
		"unsupported syscall: ioctl due to missing const __NR_ioctl",
		"compile: failed, 2 error(s)\n",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is %q, want it to contain %q", stderr, want)
		}
	}
	if stdout != "" {
		t.Errorf("stdout is %q, want empty", stdout)
	}
}

// figure returns one capture of the verdict line as an integer.
func figure(t *testing.T, groups []string, index int, name string) int {
	t.Helper()
	value, err := strconv.Atoi(groups[index])
	if err != nil {
		t.Fatalf("the %s figure %q is not an integer: %v", name, groups[index], err)
	}
	return value
}

// assertVerdict matches the stdout line and checks the figures the compile
// gate reads. wantConsts is the sidecar count, wantOwn the syscalls the
// description declares. Six syz_builtinN pseudo-syscalls are added to every
// compile by pkg/compiler, which tools/syzlang_gen.py subtracts under the same
// name.
func assertVerdict(t *testing.T, stdout string, wantConsts, wantOwn int) {
	t.Helper()
	groups := verdictRE.FindStringSubmatch(stdout)
	if groups == nil {
		t.Fatalf("stdout is %q, want a compile: OK verdict line", stdout)
	}
	const builtinSyscalls = 6
	if got := figure(t, groups, 1, "const"); got != wantConsts {
		t.Errorf("%d const(s) loaded, want %d", got, wantConsts)
	}
	if got := figure(t, groups, 2, "syscall"); got != wantOwn+builtinSyscalls {
		t.Errorf("%d syscall(s), want %d own plus %d builtin",
			got, wantOwn, builtinSyscalls)
	}
	if got := figure(t, groups, 3, "resource"); got < 1 {
		t.Errorf("%d resource(s), want the fd resource counted", got)
	}
	if got := figure(t, groups, 5, "unsupported"); got != 0 {
		t.Errorf("%d unsupported, want 0", got)
	}
}

func TestValidDescriptionCompiles(t *testing.T) {
	dir := descDir(t, map[string]string{
		"min.txt":       validDesc,
		"min.txt.const": validConst,
	})
	code, stdout, stderr := call("-dir", dir)
	if code != wantOK {
		t.Fatalf("exit code is %d, want %d, stderr %q", code, wantOK, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr is %q, want empty", stderr)
	}
	assertVerdict(t, stdout, 2, 2)
}

// The same success path through the branch that builds an empty const file
// because the sidecar glob matches nothing.
func TestPseudoSyscallsCompileWithNoSidecar(t *testing.T) {
	dir := descDir(t, map[string]string{"min.txt": pseudoDesc})
	code, stdout, stderr := call("-dir", dir)
	if code != wantOK {
		t.Fatalf("exit code is %d, want %d, stderr %q", code, wantOK, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr is %q, want empty", stderr)
	}
	assertVerdict(t, stdout, 0, 2)
}

// -arch selects the column read out of the sidecar. A sidecar carrying only
// amd64 values yields no consts for arm64, and the compile then fails the same
// way an absent sidecar does.
func TestArchSelectsTheConstColumn(t *testing.T) {
	dir := descDir(t, map[string]string{
		"min.txt":       validDesc,
		"min.txt.const": validConst,
	})
	code, _, stderr := call("-dir", dir, "-arch", "arm64")
	if code != wantFail {
		t.Errorf("exit code is %d, want %d", code, wantFail)
	}
	if want := "compile: failed, 2 error(s)\n"; !strings.Contains(stderr, want) {
		t.Errorf("stderr is %q, want it to contain %q", stderr, want)
	}
}
