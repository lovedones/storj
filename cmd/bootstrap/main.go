// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/storj/bootstrap"
	"storj.io/storj/bootstrap/bootstrapdb"
	"storj.io/storj/internal/fpath"
	"storj.io/storj/pkg/cfgstruct"
	"storj.io/storj/pkg/process"
)

var (
	rootCmd = &cobra.Command{
		Use:   "bootstrap",
		Short: "bootstrap",
	}
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the bootstrap server",
		RunE:  cmdRun,
	}
	setupCmd = &cobra.Command{
		Use:         "setup",
		Short:       "Create config files",
		RunE:        cmdSetup,
		Annotations: map[string]string{"type": "setup"},
	}

	runCfg   bootstrap.Config
	setupCfg bootstrap.Config

	confDir     string
	identityDir string
	isDev       bool
)

const (
	defaultServerAddr = ":28967"
)

func init() {
	defaultConfDir := fpath.ApplicationDir("storj", "bootstrap")
	defaultIdentityDir := fpath.ApplicationDir("storj", "identity", "bootstrap")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &confDir, "config-dir", defaultConfDir, "main directory for bootstrap configuration")
	cfgstruct.SetupFlag(zap.L(), rootCmd, &identityDir, "identity-dir", defaultIdentityDir, "main directory for bootstrap identity credentials")
	cfgstruct.DevFlag(rootCmd, &isDev, false, "use development and test configuration settings")
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(setupCmd)
	cfgstruct.Bind(runCmd.Flags(), &runCfg, isDev, cfgstruct.ConfDir(confDir), cfgstruct.IdentityDir(identityDir))
	cfgstruct.BindSetup(setupCmd.Flags(), &setupCfg, isDev, cfgstruct.ConfDir(confDir), cfgstruct.IdentityDir(identityDir))
}

func cmdRun(cmd *cobra.Command, args []string) (err error) {
	log := zap.L()

	identity, err := runCfg.Identity.Load()
	if err != nil {
		zap.S().Fatal(err)
	}

	if err := runCfg.Verify(log); err != nil {
		log.Sugar().Error("Invalid configuration: ", err)
		return err
	}

	ctx := process.Ctx(cmd)
	if err := process.InitMetricsWithCertPath(ctx, nil, runCfg.Identity.CertPath); err != nil {
		zap.S().Error("Failed to initialize telemetry batcher: ", err)
	}

	db, err := bootstrapdb.New(bootstrapdb.Config{
		Kademlia: runCfg.Kademlia.DBPath,
	})
	if err != nil {
		return errs.New("Error starting master database on bootstrap: %+v", err)
	}

	defer func() {
		err = errs.Combine(err, db.Close())
	}()

	err = db.CreateTables()
	if err != nil {
		return errs.New("Error creating tables for master database on bootstrap: %+v", err)
	}

	peer, err := bootstrap.New(log, identity, db, runCfg)
	if err != nil {
		return err
	}

	runError := peer.Run(ctx)
	closeError := peer.Close()

	return errs.Combine(runError, closeError)
}

func cmdSetup(cmd *cobra.Command, args []string) (err error) {
	setupDir, err := filepath.Abs(confDir)
	if err != nil {
		return err
	}

	valid, _ := fpath.IsValidSetupDir(setupDir)
	if !valid {
		return fmt.Errorf("bootstrap configuration already exists (%v)", setupDir)
	}

	err = os.MkdirAll(setupDir, 0700)
	if err != nil {
		return err
	}

	overrides := map[string]interface{}{}

	serverAddress := cmd.Flag("server.address")
	if !serverAddress.Changed {
		overrides[serverAddress.Name] = defaultServerAddr
	}

	kademliaBootstrapAddr := cmd.Flag("kademlia.bootstrap-addr")
	if !kademliaBootstrapAddr.Changed {
		overrides[kademliaBootstrapAddr.Name] = "localhost" + defaultServerAddr
	}

	return process.SaveConfigWithAllDefaults(cmd.Flags(), filepath.Join(setupDir, "config.yaml"), overrides)
}

func main() {
	process.Exec(rootCmd)
}
