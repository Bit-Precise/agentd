// Command protogen compiles proto/agentd/v1/*.proto and writes the Go code
// with the official protoc-gen-go generator, without needing protoc.
//
//	go run ./tools/protogen
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/cmd/protoc-gen-go/internal_gengo"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "protogen:", err)
		os.Exit(1)
	}
}

func run() error {
	const root = "proto"
	var files []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".proto") {
			rel, _ := filepath.Rel(root, p)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(files)
	comp := protocompile.Compiler{
		Resolver:       protocompile.WithStandardImports(&protocompile.SourceResolver{ImportPaths: []string{root}}),
		SourceInfoMode: protocompile.SourceInfoStandard,
	}
	compiled, err := comp.Compile(context.Background(), files...)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var fdps []*descriptorpb.FileDescriptorProto
	var add func(fd interface {
		Path() string
	})
	_ = add
	for _, f := range compiled {
		// dependencies first
		imports := f.Imports()
		for i := 0; i < imports.Len(); i++ {
			dep := imports.Get(i).FileDescriptor
			if !seen[dep.Path()] {
				seen[dep.Path()] = true
				fdps = append(fdps, protodesc.ToFileDescriptorProto(dep))
			}
		}
		if !seen[f.Path()] {
			seen[f.Path()] = true
			fdps = append(fdps, protodesc.ToFileDescriptorProto(f))
		}
	}
	req := &pluginpb.CodeGeneratorRequest{
		FileToGenerate: files,
		ProtoFile:      fdps,
		Parameter:      proto.String("module=agentd"),
	}
	gen, err := protogen.Options{}.New(req)
	if err != nil {
		return err
	}
	for _, f := range gen.Files {
		if f.Generate {
			internal_gengo.GenerateFile(gen, f)
		}
	}
	resp := gen.Response()
	if resp.Error != nil {
		return fmt.Errorf("%s", resp.GetError())
	}
	for _, out := range resp.File {
		name := filepath.FromSlash(out.GetName())
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(name, []byte(out.GetContent()), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", name)
	}
	return nil
}
