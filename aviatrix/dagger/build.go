package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"dagger.io/dagger"
	"golang.org/x/exp/maps"
)

// DevInstallBase is the prefix where we install libraries and tools
// that are needed to build Traffic Server. We use /opt/ats here because
// the libraries will be included in the final Ubuntu package.
const DevInstallBase = "/opt/ats"

// TrafficServerInstallDir is the path TrafficServer is installed in.
const TrafficServerInstallDir = "/opt/ats/ats_10.0.0"

// writeExecScript wraps the given command-line in a trivial bash
// script. This is useful for cases where we want to run something in
// a build step, but also give developers the opportunity to run the
// identical command later.
func writeExecScript(cmd ...string) dagger.ContainerWithNewFileOpts {
	b := strings.Builder{}

	b.WriteString("#! /usr/bin/env bash\n\nexec \\\n")

	for _, s := range cmd {
		b.WriteString(s)
		b.WriteString(" \\\n")
	}

	b.WriteString(`"$@"`)

	return dagger.ContainerWithNewFileOpts{
		Permissions: 0755,
		Contents:    b.String(),
	}
}

// makeInstall runs "make" and then "make install". In makeArgs is
// provided, these are appended to the "make" command.
func makeInstall(makeArgs ...string) dagger.WithContainerFunc {
	return func(container *dagger.Container) *dagger.Container {
		return container.
			WithExec([]string{"sh", "-c", "echo MAKEFLAGS=$MAKEFLAGS"}).
			WithExec(append([]string{"make"}, makeArgs...)).
			WithExec([]string{"make", "install"})
	}
}

func aptUpdate() dagger.WithContainerFunc {
	return func(container *dagger.Container) *dagger.Container {
		cmd := []string{"env", "DEBIAN_FRONTEND=noninteractive",
			"apt-get", "update", "--no-install-recommends", "--quiet", "--assume-yes",
		}
		return container.WithExec(cmd)
	}
}

func aptInstall(packages ...string) dagger.WithContainerFunc {
	return func(container *dagger.Container) *dagger.Container {
		cmd := []string{"env", "DEBIAN_FRONTEND=noninteractive",
			"apt-get", "install", "--no-install-recommends", "--assume-yes",
		}

		cmd = append(cmd, packages...)
		return container.WithExec(cmd)
	}
}

func withHostFiles(client *dagger.Client, files map[string]string) dagger.WithContainerFunc {
	// Make a stable list of destination files so that we don't bust the cache.
	targets := maps.Keys(files)
	sort.Strings(targets)

	return func(container *dagger.Container) *dagger.Container {
		for _, t := range targets {
			container = container.WithFile(t, client.Host().File(files[t]))
		}
		return container
	}
}

// getTrafficServerSourceVersion generates a version string that is
// passed in to the Traffic Server build. If we are building a git
// repository directly, use the branch or tag name.
func getTrafficServerSourceVersion(client *dagger.Client) string {
	if strings.HasPrefix(TrafficServerDir, "git@") {
		opts := dagger.GitOpts{}

		// If we are running in a local dev environment, then we can use SSH_AUTH_SOCK
		// to do an authenticated pull of the repository.
		if sshAgentPath := os.Getenv("SSH_AUTH_SOCK"); sshAgentPath != "" {
			opts.SSHAuthSocket = client.Host().UnixSocket(sshAgentPath)
		}

		repo := client.Git(TrafficServerDir, opts)

		// Building from "master" is a reasonably intuitive default.
		name := "master"
		ref := repo.Tag(name)

		// The tag and branch flags are mutually exclusive, so
		// it doesn't matter which order we check them in.
		switch {
		case TrafficServerBranch != "":
			name = TrafficServerBranch
			ref = repo.Branch(TrafficServerBranch)
		case TrafficServerTag != "":
			name = TrafficServerTag
			ref = repo.Tag(TrafficServerTag)
		}

		commit, err := ref.Commit(context.Background())
		if err != nil {
			Errorf("Unable to determine Git commit: %s", err) // yet?
			os.Exit(1)
		}

		return fmt.Sprintf("%s-%s", name, commit[:min(len(commit), 10)])
	}

	// NOTE: GitHub PRs don't clone the tags, so we need to set --always as a fallback.
	cmd := exec.Command("git", "describe", "--always", "--dirty=+dirty")
	cmd.Dir = Must(filepath.Abs(TrafficServerDir))
	out, err := cmd.CombinedOutput()
	if err != nil {
		if len(out) != 0 {
			Errorf("%s", strings.TrimSpace(string(out)))
		}
		Errorf("git describe failed: %s", err)
		os.Exit(1)
	}

	return strings.TrimSpace(string(out))
}

func bindTrafficServerSources(client *dagger.Client) *dagger.Directory {
	if strings.HasPrefix(TrafficServerDir, "git@") {
		repo := client.Git(TrafficServerDir)
		opts := dagger.GitRefTreeOpts{}

		// If we are running in a local dev environment, then we can use SSH_AUTH_SOCK
		// to do an authenticated pull of the repository.
		if sshAgentPath := os.Getenv("SSH_AUTH_SOCK"); sshAgentPath != "" {
			opts.SSHAuthSocket = client.Host().UnixSocket(sshAgentPath)
		}

		// The tag and branch flags are mutually exclusive, so
		// it doesn't matter which order we check them in.
		if TrafficServerBranch != "" {
			return repo.Branch(TrafficServerBranch).Tree(opts)
		}

		if TrafficServerTag != "" {
			return repo.Tag(TrafficServerTag).Tree(opts)
		}

		// Building from "master" is a reasonably intuitive default.
		return repo.Tag("master").Tree(opts)
	}

	if strings.HasPrefix(TrafficServerDir, "https://") {
		Errorf("HTTPS Git repositories are not supported") // yet?
		os.Exit(1)
	}

	// Now, assume that TrafficServerDir is a local directory path.
	// NOTE: Dagger needs an absolute path to copy a directory from outside
	// our current workdir.
	repoBaseDir := Must(filepath.Abs(TrafficServerDir))

	// Copy the build source from the host to the container. We exclude
	// directories with build tooling so that changes to packaging
	// and scripts don't blow the Dagger cache.
	return client.Host().Directory(
		repoBaseDir,
		dagger.HostDirectoryOpts{
			Exclude: []string{
				".git/",
				".github/",
				"aviatrix/dagger",
				"aviatrix/build",
				"build/_aux",
				"copy-for-docker.tgz",
			},
		},
	)

}

// bindCloudnProtobufs returns the "proto" subdirectory of the cloudn repository.
func bindCloudnProtobufs(client *dagger.Client) *dagger.Directory {
	// TODO(jpeach) first check if we have a GitHub access
	// token, and use that. We would use the access token in GitHub
	// Actions builds.

	// If we are running in a local dev environment, then we can use SSH_AUTH_SOCK
	// to do an authenticated pull of the cloudn repository.
	if sshAgentPath := os.Getenv("SSH_AUTH_SOCK"); sshAgentPath != "" {
		opts := dagger.GitRefTreeOpts{
			SSHAuthSocket: client.Host().UnixSocket(sshAgentPath),
		}

		repo := client.Git("git@github.com:AviatrixDev/cloudn.git")

		if CloudnTag != "" {
			return repo.Tag(CloudnTag).Tree(opts).Directory("proto")
		}

		if CloudnBranch != "" {
			return repo.Branch(CloudnBranch).Tree(opts).Directory("proto")
		}

		return repo.Branch("master").Tree(opts).Directory("proto")
	}

	// If there's no SSH agent, then we assume that the cloudn
	// repository is checked out next to our local repository.

	// Absolute path to the top of the current repository.
	repoBaseDir := Must(filepath.Abs("../.."))
	return client.Host().Directory(
		path.Join(repoBaseDir, "../cloudn/proto"),
	)
}

func buildJemalloc(client *dagger.Client, container *dagger.Container) *dagger.Container {
	const srcdir = "/src/jemalloc"
	const vers = "5.3.0"

	tarball := client.HTTP(fmt.Sprintf(
		"https://github.com/jemalloc/jemalloc/releases/download/%s/jemalloc-%s.tar.bz2", vers, vers))

	return container.
		With(aptInstall("libunwind-dev")).
		WithExec([]string{"mkdir", "-p", srcdir}).
		WithWorkdir(srcdir).
		WithFile(path.Join(srcdir, "jemalloc-source.tgz"), tarball).
		WithExec([]string{"tar", "--strip-components=1", "-xf", "jemalloc-source.tgz"}).
		WithExec([]string{
			"./configure",
			"--prefix=" + DevInstallBase,
			"--enable-prof",
			"--enable-prof-libunwind",
		}).
		With(makeInstall())
}

func buildOpenssl(client *dagger.Client, container *dagger.Container) *dagger.Container {
	const srcdir = "/src/openssl"
	const prefix = DevInstallBase

	branch := client.Git("https://github.com/openssl/openssl").
		Tag("openssl-3.0.13").
		Tree()

	return container.
		WithDirectory(srcdir, branch).
		WithWorkdir(srcdir).
		WithExec([]string{
			"./config",
			"--release",
			"--prefix=" + prefix,
			"--libdir=" + path.Join(prefix, "lib"), // Override the "lib64" default.
			"no-tests",
			"no-makedepend",
			// TODO(jpeach) master also has no-apps and no-docs build options
		}).
		With(makeInstall())
}

func buildGrpc(client *dagger.Client, container *dagger.Container) *dagger.Container {
	srcdir := "/src/grpc"
	builddir := "/build/grpc"
	ssldir := DevInstallBase

	// Note that dagger recursively checks out submodules without
	// special configuration.
	branch := client.Git("https://github.com/grpc/grpc").
		Branch("v1.48.0").
		Tree()

	// See also https://github.com/grpc/grpc/blob/master/BUILDING.md.
	return container.
		With(aptInstall("cmake")).
		WithDirectory(srcdir, branch).
		WithExec([]string{"mkdir", "-p", builddir}).
		WithWorkdir(builddir).
		WithExec([]string{
			"/usr/bin/cmake",
			"-DCMAKE_INSTALL_PREFIX=" + DevInstallBase,
			"-DCMAKE_BUILD_TYPE:STRING=Release",
			// Enable shared libraries.
			"-DBUILD_SHARED_LIBS=ON",
			// Force cmake to set rpath so that gRPC tools work.
			"-DCMAKE_SKIP_RPATH=FALSE",
			"-DCMAKE_INSTALL_RPATH=" + path.Join(DevInstallBase, "lib"),
			"-DCMAKE_CXX_STANDARD=17",
			"-DCMAKE_CXX_STANDARD_REQUIRED=On",
			"-DCMAKE_CXX_EXTENSIONS=On",
			// Note that this installs abseil as a side-effect.
			"-DgRPC_INSTALL=ON",
			"-DgRPC_BUILD_TESTS=OFF",
			"-DgRPC_BUILD_CSHARP_EXT=OFF",
			"-DgRPC_BUILD_GRPC_CSHARP_PLUGIN=OFF",
			"-DgRPC_BUILD_GRPC_NODE_PLUGIN=OFF",
			"-DgRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN=OFF",
			"-DgRPC_BUILD_GRPC_PHP_PLUGIN=OFF",
			"-DgRPC_BUILD_GRPC_PYTHON_PLUGIN=OFF",
			"-DgRPC_BUILD_GRPC_RUBY_PLUGIN=OFF",
			// Don't the bundled BoringSSL.
			"-DgRPC_SSL_PROVIDER=package",
			"-DOPENSSL_ROOT_DIR=" + ssldir,
			// Don't use the bundled zlib.
			"-DgRPC_ZLIB_PROVIDER=package",
			srcdir,
		}).
		With(makeInstall())
}

func buildSwoc(client *dagger.Client, container *dagger.Container) *dagger.Container {
	srcdir := "/src/swoc"
	builddir := "/build/swoc"

	branch := client.Git("https://github.com/SolidWallOfCode/libswoc").
		Tag("1.5.1").
		Tree()

	return container.
		WithDirectory(srcdir, branch).
		WithExec([]string{"mkdir", "-p", builddir}).
		WithWorkdir(builddir).
		WithExec([]string{
			path.Join(DevInstallBase, "bin", "cmake"),
			"-DCMAKE_INSTALL_PREFIX=" + DevInstallBase,
			"-DCMAKE_BUILD_TYPE:STRING=Release",
			"-DLIBSWOC_TEST=OFF", // Disable the tests and examples.
			srcdir,
		}).
		With(makeInstall())
}

// setupTrafficServer does all the preparation steps for
// building Traffic Server, but not the actual build. The configure
// and make steps are saved in the build directory.
//
// Although this makes things a bit complicated, it also makes it
// possible to generate a build image where people can build Traffic
// Server manually with the correct configuration.
func setupTrafficServer(client *dagger.Client, container *dagger.Container) *dagger.Container {
	const srcdir = "/src/trafficserver"
	const cloudndir = "/src/cloudn"
	const prefix = TrafficServerInstallDir

	// Bind the cloudn protobuf directory. Note that we set
	// CLOUDN_PROTO to the cloudn repository root, because the
	// proto files include the leading "proto/" in their import paths.
	cloudnProtoDir := bindCloudnProtobufs(client)

	return container.
		// Add TrafficServer-specific dependencies.
		With(aptInstall(
			// Some tests that assume Python3 is installed.
			"python3",
			"libcap-dev",
			"libhwloc-dev",
			"libpcre3-dev",
			"libpcre2-dev",
			// So that jemalloc will link. Otherwise,
			// the Traffic Server jemalloc detection will
			// fail, but the build will continue without it.
			"libunwind8",
			"cmake",
			"pipenv",
		)).
		WithDirectory(srcdir, bindTrafficServerSources(client)).
		WithMountedDirectory(path.Join(cloudndir, "proto"), cloudnProtoDir).
		// Add the TrafficServer role account for the build and install.
		WithExec([]string{
			"useradd",
			"--create-home",
			"--shell", "/bin/bash",
			"--gid", "root",
			"--groups", "sudo",
			"--system",
			"ats-user",
		})
}

func buildTrafficServer(client *dagger.Client, container *dagger.Container) *dagger.Container {
	const srcdir = "/src/trafficserver"
	const prefix = TrafficServerInstallDir

	builder := setupTrafficServer(client, container)
	return builder.
		WithWorkdir(srcdir).
		WithExec([]string{
			"find",
			"/",
			"-name",
			"libgrpc++.a",
			"-print",
		}).
		WithExec([]string{
			"cat",
			"/src/trafficserver/CMakePresets.json",
		}).
		WithExec([]string{
			"cmake",
			"--preset",
			"aviatrix",
		}).
		WithExec([]string{
			"cmake",
			"--build",
			"build-release",
		}).
		WithExec([]string{
			"cmake",
			"--install",
			"build-release",
		}).
		// Remove garbage libtool archives.
		WithExec([]string{
			"find",
			prefix,
			"-type", "f",
			"-name", "*.la",
			"-exec", "rm", "{}", "+",
		})
}

func buildDebianPackages(
	packager *dagger.Container,
) *dagger.Container {
	const builddir = "/build/ats-10.0.0"

	base := packager.
		WithWorkdir(builddir).
		// Strip shared library symbols, see https://github.com/Debian/debhelper/blob/master/dh_strip.
		WithExec([]string{"sh", "-c",
			"find opt/ats/lib opt/ats/ats_10.0.0/lib -type f -name '*.so' -print | " +
				"xargs strip --remove-section=.comment --remove-section=.note --strip-unneeded",
		}).
		// Strip binary symbols, see https://github.com/Debian/debhelper/blob/master/dh_strip.
		WithExec([]string{"sh", "-c",
			"find opt/ats/ats_10.0.0/bin -type f -name 'traffic_*' | " +
				"xargs strip --remove-section=.comment --remove-section=.note",
		}).
		WithExec([]string{"dpkg-deb", "--build", builddir, "/build/ats-10.0.0.deb"})

	debug := packager.
		WithExec([]string{"dpkg-deb", "--build", builddir, "/build/ats-dbg-10.0.0.deb"})

	// Note that even though the deb files have different names,
	// they are still the same package as far as dpkg is concerned.
	// This means that dpkg is happy for you to install one of these
	// on top of the other (it says it's a reinstall). This seems a
	// bit weird, but desirable on balance.

	return packager.
		WithFile("/build/ats-10.0.0.deb", base.File("/build/ats-10.0.0.deb")).
		WithFile("/build/ats-dbg-10.0.0.deb", debug.File("/build/ats-dbg-10.0.0.deb"))
}

func setupDebianPackage(
	client *dagger.Client,
	trafficserver *dagger.Container,
	builder *dagger.Container,
) *dagger.Container {
	const builddir = "/build/ats-10.0.0" // Path we build the package in.
	const installdir = TrafficServerInstallDir

	repoBaseDir := Must(filepath.Abs("../.."))
	packagingDir := path.Join(repoBaseDir, "aviatrix/10_0_0.0001")

	hostFiles := map[string]string{
		"DEBIAN/control":                                  path.Join(packagingDir, "control"),
		"DEBIAN/postinst":                                 path.Join(packagingDir, "postinst"),
		"etc/logrotate.d/avx-gw-trafficserver":            path.Join(packagingDir, "logrotate/avx-gw-trafficserver"),
		"lib/systemd/system/avx-gw-trafficserver.service": path.Join(packagingDir, "avx-gw-trafficserver.service"),
	}
	manifest := path.Join(repoBaseDir, "ats-manifest")
	if _, err := os.Stat(manifest); err == nil {
		hostFiles["opt/ats/ats_10.0.0.deb.manifest"] = manifest
	}

	return builder.
		With(aptInstall(
			// So we can package the DSOs in a later step.
			"libhwloc-dev",
			// https://wiki.debian.org/Packaging/Intro
			"build-essential",
			"debhelper",
			"devscripts",
		)).
		WithExec([]string{
			"mkdir", "-p",
			path.Join(builddir, "/lib/systemd/system"),
			path.Join(builddir, "/etc/logrotate.d"),
			path.Join(builddir, "DEBIAN"),
		}).
		WithWorkdir(builddir).
		With(withHostFiles(client, hostFiles)).
		// Copy the TrafficServer build over.
		WithDirectory(
			path.Join("./", installdir),
			trafficserver.Directory(installdir),
			dagger.ContainerWithDirectoryOpts{Exclude: []string{
				"share",           // Man pages.
				"include",         // Header files.
				"lib/perl5",       // Perl bindings.
				"lib/pkgconfig",   // Pkg-config spec.
				"lib/plugin_*.so", // Remap test DSOs.
			}},
		).
		// Package the lib directory that we linked against.
		WithDirectory(
			path.Join("./", DevInstallBase, "lib"),
			trafficserver.Directory(path.Join(DevInstallBase, "lib")),
			dagger.ContainerWithDirectoryOpts{
				Exclude: []string{"cmake/", "pkgconfig/", "*.a"},
			},
		).
		// Copy libhwloc so that we don't take a dependency on a package
		// that we might not be able to install at upgrade time.
		With(func(container *dagger.Container) *dagger.Container {
			return container.WithDirectory(
				path.Join("./", installdir, "lib"),
				container.Directory("/usr/lib/x86_64-linux-gnu"),
				dagger.ContainerWithDirectoryOpts{
					Include: []string{"libhwloc.so*"},
				},
			)
		}).
		// Copy custom configs over the top.
		WithDirectory(
			path.Join("./", installdir, "etc/trafficserver"),
			client.Host().Directory(path.Join(packagingDir, "configs")),
		).
		WithExec([]string{
			"mkdir", "-p",
			path.Join("./", installdir, "etc/local_ca"),
			path.Join("./", installdir, "var/local_ca/keys"),
		}).
		WithNewFile(path.Join("./", installdir, "var/local_ca/serial.txt"), dagger.ContainerWithNewFileOpts{
			Contents: "12345",
		})
}

func buildBaseContainer(client *dagger.Client, ubuntuVersion string) *dagger.Container {
	// Start off with a base Ubuntu image, with just basic build dependencies in it.
	base := client.Container().
		From(fmt.Sprintf("ubuntu:%s", ubuntuVersion)).
		With(aptUpdate()).
		With(aptInstall(
			"autoconf",
			"automake",
			"build-essential",
			"libtool",
			"libz-dev",
			"pkg-config",
		))

	ncpu, err := ContainerNumCPUs(base)
	if err != nil {
		Errorf("failed to count container CPUs: %s", err.Error())
		ncpu = 4 // Arbitrary default.
	}

	return base.WithEnvVariable("MAKEFLAGS", fmt.Sprintf("-j%d", ncpu))
}

func buildBuilderContainer(client *dagger.Client, base *dagger.Container) *dagger.Container {
	// The builder is a dev container that has custom dependencies
	// installed in DevInstallBase.
	builder := base.
		With(func(container *dagger.Container) *dagger.Container {
			return buildOpenssl(client, container)
		}).
		With(func(container *dagger.Container) *dagger.Container {
			// We can attempt to build these packages in parallel.
			jemalloc := buildJemalloc(client, container)
			grpc := buildGrpc(client, container)
			//swoc := buildSwoc(client, container)

			// Merge the output of both builds.
			return container.
				WithDirectory(DevInstallBase, jemalloc.Directory(DevInstallBase)).
				WithDirectory(DevInstallBase, grpc.Directory(DevInstallBase))
		})

	// Now copy the installed packages back to base so that we don't
	// have any intermediate artifacts.
	return base.
		WithDirectory(DevInstallBase, builder.Directory(DevInstallBase))
}
