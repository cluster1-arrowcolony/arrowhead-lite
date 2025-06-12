package health

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

type HealthChecker struct {
	registry        Registry
	logger          *logrus.Logger
	checkInterval   time.Duration
	inactiveTimeout time.Duration
	cleanupInterval time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
}

func newHealthChecker(registry Registry, logger *logrus.Logger, checkInterval, inactiveTimeout, cleanupInterval time.Duration) *HealthChecker {
	ctx, cancel := context.WithCancel(context.Background())

	hc := &HealthChecker{
		registry:        registry,
		logger:          logger,
		checkInterval:   checkInterval,
		inactiveTimeout: inactiveTimeout,
		cleanupInterval: cleanupInterval,
		ctx:             ctx,
		cancel:          cancel,
	}

	go hc.startHealthChecking()
	go hc.startCleanupWorker()

	return hc
}

// startHealthChecking starts the periodic health checking routine
func (hc *HealthChecker) startHealthChecking() {
	ticker := time.NewTicker(hc.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-hc.ctx.Done():
			return
		case <-ticker.C:
			hc.performHealthChecks()
		}
	}
}

// Close shuts down the health checker
func (hc *HealthChecker) Close() error {
	hc.cancel()
	return nil
}
