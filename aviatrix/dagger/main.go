package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"dagger.io/dagger"
)

// BaseUbuntuVersion is the Ubuntu release version to build for.
var BaseUbuntuVersion string

// TrafficServerDir is the path to the Traffic Server source code.
// If this is a git or https URL, then we pull the Git repository.
// Otherwise, we assume it is a local path.
var TrafficServerDir string

// TrafficServerTag is the Traffic Server source tag. Mutually
// exclusive with the branch. Ignored unless we are building a git
// repository.
var TrafficServerTag string

// TrafficServerBranch is the Traffic Server source branch. Mutually
// exclusive with the tag. Ignored unless we are building a git
// repository.
var TrafficServerBranch string

// CloudnTag is the tag at which we pull protobuf definitions from
// the cloudn repository. Default is to use the master branch. Mutually
// exclusive with CloudnBranch.
var CloudnTag string

// CloudnBranch is the branch from which we pull protobuf definitions from
// the cloudn repository. Default is to use the master branch. Mutually
// exclusive with CloudnTag.
var CloudnBranch string

// ContainerNumCPUs inspects the given container and returns the number of available CPUs.
func ContainerNumCPUs(container *dagger.Container) (int, error) {
	// procfs is only mounbtedfor processes, so we need to
	// sample it with an exec before we can copy it out.
	container = container.WithExec(
		[]string{"cat", "/proc/cpuinfo"},
		dagger.ContainerWithExecOpts{RedirectStdout: "/tmp/cpuinfo"},
	)

	cpuInfo, err := container.File("/tmp/cpuinfo").Contents(context.Background())
	if err != nil {
		return -1, err
	}

	count := 0
	scanner := bufio.NewScanner(strings.NewReader(cpuInfo))

	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), ": ", 2)

		// Skip over empty lines.
		if len(fields) != 2 {
			continue
		}

		if strings.TrimSpace(fields[0]) == "processor" {
			count++
		}
	}

	return count, nil
}

func Successf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "✅  %s\n", fmt.Sprintf(format, args...))
}

func Errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "✴️  %s\n", fmt.Sprintf(format, args...))
}

func Must[T any](value T, err error) T {
	if err != nil {
		Errorf(err.Error())
		os.Exit(1)
	}

	return value
}

func ExportContainerImage(
	ctx context.Context,
	container *dagger.Container,
	repoName string,
	tagName string,
) error {
	buildImagePath := path.Join("images", repoName, tagName+".tgz")
	if _, err := container.Export(ctx, buildImagePath); err != nil {
		return err
	}

	Successf("exported build container image to %q", buildImagePath)

	// Load the exported OCI image into the local Docker instance.
	// Note that we have to load, not import.
	cmdImport := exec.Command("docker", "load", "--quiet", "--input", buildImagePath)
	out, err := cmdImport.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to export builder image: %w", err)
	}

	Successf("imported build container image from %q", buildImagePath)

	// Capture the image ID from the output of the load
	// command so that we can tag it. Remember that the
	// first result from Submatch is the full matched
	// sequence, so the capture group is the second match.
	r := regexp.MustCompile("Loaded image ID: ([:a-z0-9]+)")
	matches := r.FindStringSubmatch(string(out))
	if len(matches) == 0 {
		Errorf("failed to match image ID from Docker output %q", string(out))
		os.Exit(1)
	}

	fullName := fmt.Sprintf("%s:%s", repoName, tagName)
	cmdTag := exec.Command("docker", "tag", matches[1], fullName)
	if out, err := cmdTag.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to tag builder image: %s", string(out))
	}

	Successf("tagged build container image %q as %q", matches[1], fullName)

	return nil
}

func packageCmd(ctx context.Context, client *dagger.Client) error {
	base := buildBaseContainer(client, BaseUbuntuVersion)
	builder := buildBuilderContainer(client, base)

	// Now build TrafficServer in the builder container.
	trafficserver := buildTrafficServer(client, builder)

	// Fork a container off the base image to wrap the TrafficServer
	// build in a Debian package.
	packager := buildDebianPackages(setupDebianPackage(client, trafficserver, base))

	for _, pkg := range []string{"ats-10.0.0.deb", "ats-dbg-10.0.0.deb"} {
		// Copy the final debian package out of the packager container.
		packagePath := path.Join("packages", BaseUbuntuVersion, pkg)
		packageFile := client.Directory().
			WithFile(packagePath, packager.File("/build/"+pkg))

		if _, err := packageFile.Export(ctx, "."); err != nil {
			return fmt.Errorf("failed to export Debian package: %s", err.Error())
		}

		Successf("wrote Debian package to %s", packagePath)
	}

	return nil
}

func packagingImageCmd(ctx context.Context, client *dagger.Client) error {
	base := buildBaseContainer(client, BaseUbuntuVersion)
	builder := buildBuilderContainer(client, base)
	trafficserver := buildTrafficServer(client, builder)
	packager := setupDebianPackage(client, trafficserver, builder)

	return ExportContainerImage(ctx, packager, "trafficserver-packaging", BaseUbuntuVersion)
}

func buildImageCmd(ctx context.Context, client *dagger.Client) error {
	base := buildBaseContainer(client, BaseUbuntuVersion)
	builder := buildBuilderContainer(client, base)

	// Do TrafficServer build setup so that the exported
	// image contains the configure and make steps that
	// the package build would use.
	trafficserver := setupTrafficServer(client, builder)

	return ExportContainerImage(ctx, trafficserver, "trafficserver-devel", BaseUbuntuVersion)
}

func regressionTestsCmd(ctx context.Context, client *dagger.Client) error {
	base := buildBaseContainer(client, BaseUbuntuVersion)
	builder := buildBuilderContainer(client, base)

	trafficserver := setupTrafficServer(client, builder).
		WithExec([]string{"./conf.sh", "--enable-tests"}).
		With(makeInstall()).
		WithExec([]string{
			path.Join(TrafficServerInstallDir, "bin/traffic_server"),
			"--clear_hostdb", "--clear_cache", "--regression", "1",
		})

	if _, err := trafficserver.Sync(ctx); err != nil {
		return fmt.Errorf("regression tests failed: %s", err)
	}

	Successf("regression tests passed")
	return nil
}

func unitTestsCmd(ctx context.Context, client *dagger.Client) error {
	base := buildBaseContainer(client, BaseUbuntuVersion)
	builder := buildBuilderContainer(client, base)
	trafficserver := buildTrafficServer(client, builder).
		// First build the tests without running any, to catch build errors.
		WithExec([]string{"make", "check", "TESTS="}).
		// Next, run the tests.
		WithExec([]string{"make", "check"})

	if _, err := trafficserver.Sync(ctx); err != nil {
		return fmt.Errorf("unit tests failed: %s", err)
	}

	Successf("unit tests passed")
	return nil
}

func main() {
	var daggerCtx context.Context
	var daggerClient *dagger.Client

	defer func() {
		if daggerClient != nil {
			daggerClient.Close()
		}
	}()

	rootCmd := cobra.Command{
		Use: path.Base(os.Args[0]),
		PersistentPreRunE: func(*cobra.Command, []string) error {
			var err error
			daggerCtx = context.Background()

			// Initialize a Dagger client.
			daggerClient, err = dagger.Connect(daggerCtx, dagger.WithLogOutput(os.Stdout))
			return err
		},
	}

	rootCmd.PersistentFlags().
		StringVar(&BaseUbuntuVersion, "ubuntu", "22.04", "Base Ubuntu release version")

	rootCmd.PersistentFlags().
		StringVar(&TrafficServerDir, "source", "../..", "Traffic Server source repository or directory path")

	rootCmd.PersistentFlags().
		StringVar(&TrafficServerBranch, "branch", "", "Traffic Server source branch")

	rootCmd.PersistentFlags().
		StringVar(&TrafficServerTag, "tag", "", "Traffic Server source tag")

	rootCmd.PersistentFlags().
		StringVar(&CloudnTag, "cloudn-tag", "", "Cloudn source repository tag")

	rootCmd.PersistentFlags().
		StringVar(&CloudnBranch, "cloudn-branch", "", "Cloudn source repository branch")

	rootCmd.AddCommand(
		&cobra.Command{
			Use:   "package",
			Short: "Build the Ubuntu .deb package",
			RunE: func(cmd *cobra.Command, args []string) error {
				return packageCmd(daggerCtx, daggerClient)
			},
		},
		&cobra.Command{
			Use:   "packaging-image",
			Short: "Build a Docker image for packaging",
			RunE: func(cmd *cobra.Command, args []string) error {
				return packagingImageCmd(daggerCtx, daggerClient)
			},
		},
		&cobra.Command{
			Use:   "build-image",
			Short: "Build a Docker image for local development",
			RunE: func(cmd *cobra.Command, args []string) error {
				return buildImageCmd(daggerCtx, daggerClient)
			},
		},
		&cobra.Command{
			Use:   "regression-tests",
			Short: "Run Traffic Server regression tests",
			RunE: func(cmd *cobra.Command, args []string) error {
				return regressionTestsCmd(daggerCtx, daggerClient)
			},
		},
		&cobra.Command{
			Use:   "unit-tests",
			Short: "Run Traffic Server unit tests",
			RunE: func(cmd *cobra.Command, args []string) error {
				return unitTestsCmd(daggerCtx, daggerClient)
			},
		},
	)

	for _, c := range rootCmd.Commands() {
		c.MarkFlagsMutuallyExclusive("tag", "branch")
		c.MarkFlagsMutuallyExclusive("cloudn-tag", "cloudn-branch")
	}

	if err := rootCmd.Execute(); err != nil {
		Errorf("%s", err)
	}
}
