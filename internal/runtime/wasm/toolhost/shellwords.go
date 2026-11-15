package toolhost

import (
	"errors"
	"strings"
)

// splitShellWords splits a command line into words the way a POSIX shell
// does, and nothing more: a WASM sandbox has no shell, so there is no
// expansion, no globbing, no pipes or redirects, and "|" or ">" are plain
// words. Quoting still works, so "python -c 'print(1 + 2)'" reaches the
// module as three arguments; strings.Fields would cut the code apart.
//
//   - Blanks (space, tab, newline) separate words outside quotes.
//   - '...' keeps everything up to the next ' literally.
//   - "..." keeps everything, except that a backslash escapes $ ` " \ and
//     newline (a backslash-newline is removed).
//   - Outside quotes a backslash keeps the next character literally, and a
//     backslash-newline is removed.
//   - An empty pair of quotes makes an empty word.
func splitShellWords(s string) ([]string, error) {
	var (
		words   []string
		cur     strings.Builder
		inWord  bool
		runes   = []rune(s)
		errQuot = errors.New("unterminated quote in command")
	)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case r == ' ' || r == '\t' || r == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case r == '\\':
			if i+1 >= len(runes) {
				return nil, errors.New("command ends with a backslash")
			}
			i++
			if runes[i] != '\n' {
				cur.WriteRune(runes[i])
				inWord = true
			}
		case r == '\'':
			inWord = true
			end := -1
			for j := i + 1; j < len(runes); j++ {
				if runes[j] == '\'' {
					end = j
					break
				}
			}
			if end < 0 {
				return nil, errQuot
			}
			cur.WriteString(string(runes[i+1 : end]))
			i = end
		case r == '"':
			inWord = true
			closed := false
			for i++; i < len(runes); i++ {
				c := runes[i]
				if c == '"' {
					closed = true
					break
				}
				if c == '\\' && i+1 < len(runes) {
					switch next := runes[i+1]; next {
					case '$', '`', '"', '\\':
						cur.WriteRune(next)
						i++
						continue
					case '\n':
						i++
						continue
					}
				}
				cur.WriteRune(c)
			}
			if !closed {
				return nil, errQuot
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}
