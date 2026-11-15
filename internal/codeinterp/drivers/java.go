package drivers

import (
	_ "embed"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

//go:embed java_driver.java
var javaDriver []byte

// javaArgs runs the driver as a single-file source program (JDK 11+).
// UTF-8 everywhere: a container's POSIX locale would otherwise make JDK 17
// print "?" for every non-ASCII character. The --add-opens lets the driver
// set a run's environment variables for System.getenv and child processes.
var javaArgs = []string{
	"-Dfile.encoding=UTF-8",
	"-Dsun.stdout.encoding=UTF-8",
	"-Dsun.stderr.encoding=UTF-8",
	"-Dstdout.encoding=UTF-8",
	"-Dstderr.encoding=UTF-8",
	"--add-opens=java.base/java.util=ALL-UNNAMED",
}

func init() {
	register(Driver{
		Language: codeinterp.LangJava,
		Programs: []string{"java"},
		// The .java extension is what makes java run it as source.
		FileName: "java_driver.java",
		Script:   javaDriver,
		Args: func(program, scriptPath string) []string {
			args := append([]string{program}, javaArgs...)
			return append(args, scriptPath)
		},
	})
}
