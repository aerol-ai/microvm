package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// readIntConst returns the value of the package-level integer constant name
// declared in the non-test Go files of dir. The value may be an integer
// literal, another constant of the same package, or a sum or difference of
// those. Anything else (a typed expression, iota, a constant declared in
// two files) is an error: the release job fails rather than publishing a
// wrong number.
func readIntConst(dir, name string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", dir, err)
	}
	fset := token.NewFileSet()
	consts := map[string]ast.Expr{}
	where := map[string]string{}
	for _, e := range entries {
		file := e.Name()
		if e.IsDir() || !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, file), nil, parser.SkipObjectResolution)
		if err != nil {
			return 0, fmt.Errorf("parse %s: %w", file, err)
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, ident := range vs.Names {
					if i >= len(vs.Values) {
						continue // an implicit repeat of the previous expression (iota)
					}
					if prev, dup := where[ident.Name]; dup {
						return 0, fmt.Errorf("constant %s is declared in both %s and %s", ident.Name, prev, file)
					}
					consts[ident.Name] = vs.Values[i]
					where[ident.Name] = file
				}
			}
		}
	}
	if _, ok := consts[name]; !ok {
		return 0, fmt.Errorf("constant %s not found in %s", name, dir)
	}
	return evalIntConst(name, consts, map[string]bool{})
}

func evalIntConst(name string, consts map[string]ast.Expr, visiting map[string]bool) (int, error) {
	expr, ok := consts[name]
	if !ok {
		return 0, fmt.Errorf("constant %s not found", name)
	}
	if visiting[name] {
		return 0, fmt.Errorf("constant %s refers to itself", name)
	}
	visiting[name] = true
	defer delete(visiting, name)
	return evalIntExpr(expr, consts, visiting)
}

func evalIntExpr(expr ast.Expr, consts map[string]ast.Expr, visiting map[string]bool) (int, error) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.INT {
			return 0, fmt.Errorf("%s is not an integer literal", e.Value)
		}
		n, err := strconv.ParseInt(e.Value, 0, 64)
		if err != nil {
			return 0, fmt.Errorf("integer literal %s: %w", e.Value, err)
		}
		return int(n), nil
	case *ast.Ident:
		return evalIntConst(e.Name, consts, visiting)
	case *ast.ParenExpr:
		return evalIntExpr(e.X, consts, visiting)
	case *ast.BinaryExpr:
		if e.Op != token.ADD && e.Op != token.SUB {
			return 0, fmt.Errorf("unsupported operator %s", e.Op)
		}
		x, err := evalIntExpr(e.X, consts, visiting)
		if err != nil {
			return 0, err
		}
		y, err := evalIntExpr(e.Y, consts, visiting)
		if err != nil {
			return 0, err
		}
		if e.Op == token.ADD {
			return x + y, nil
		}
		return x - y, nil
	}
	return 0, fmt.Errorf("unsupported constant expression %T", expr)
}
