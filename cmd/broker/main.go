package main

import (
	"context"
	"fmt"

	"github.com/knadh/koanf/v2"
	"github.com/nowsecure/nowsecure-network-broker/internal/broker"
	"github.com/nowsecure/nowsecure-network-broker/internal/config"
	"github.com/nowsecure/nowsecure-network-broker/logger"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func main() {
	c, cfg := root()
	c.AddCommand(
		NewStartCmd(cfg),
	)

	ctx := context.Background()
	if err := c.ExecuteContext(ctx); err != nil {
		log.Fatal().Err(err).Send()
	}
}

func root() (*cobra.Command, *config.Config) {
	var configFiles []string
	cfg := &config.Config{}
	c := &cobra.Command{
		Use:           "broker",
		Short:         "broker",
		SilenceUsage:  false,
		SilenceErrors: false,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := config.LoadConfig(ctx, koanf.New("."), configFiles, cfg); err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			ctx = logger.NewLogger(cfg.Log.Pretty, cfg.Log.Level).WithContext(cmd.Context())
			cmd.SetContext(ctx)
			return nil
		},
	}

	c.PersistentFlags().StringSliceVarP(&configFiles, "config", "c", []string{
		"./config.yaml",
	}, "config file paths (can be specified multiple times, later files override earlier ones)")
	return c, cfg
}

func NewStartCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start the broker",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			zerolog.Ctx(ctx).Info().Msg("starting broker")
			return broker.New(ctx, cfg).Start()
		},
	}
}
