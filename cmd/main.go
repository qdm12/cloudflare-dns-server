package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata"

	_ "github.com/breml/rootcerts"
	"github.com/qdm12/dns/internal/config"
	"github.com/qdm12/dns/internal/health"
	"github.com/qdm12/dns/internal/models"
	"github.com/qdm12/dns/internal/splash"
	"github.com/qdm12/dns/pkg/blacklist"
	"github.com/qdm12/dns/pkg/check"
	"github.com/qdm12/dns/pkg/doh"
	"github.com/qdm12/dns/pkg/dot"
	"github.com/qdm12/dns/pkg/nameserver"
	"github.com/qdm12/golibs/logging"
	"github.com/qdm12/goshutdown"
)

var (
	version   string
	buildDate string //nolint:gochecknoglobals
	commit    string //nolint:gochecknoglobals
)

func main() {
	buildInfo := models.BuildInformation{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
	}

	ctx := context.Background()
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	args := os.Args
	logger := logging.NewParent(logging.Settings{})
	configReader := config.NewReader(logger)

	errorCh := make(chan error)
	go func() {
		errorCh <- _main(ctx, buildInfo, args, logger, configReader)
	}()

	select {
	case <-ctx.Done():
		logger.Warn("Caught OS signal, shutting down\n")
		stop()
	case err := <-errorCh:
		close(errorCh)
		if err == nil { // expected exit such as healthcheck
			os.Exit(0)
		}
		logger.Error(err)
	}

	const shutdownGracePeriod = 5 * time.Second
	timer := time.NewTimer(shutdownGracePeriod)
	select {
	case <-errorCh:
		if !timer.Stop() {
			<-timer.C
		}
		logger.Info("Shutdown successful")
	case <-timer.C:
		logger.Warn("Shutdown timed out")
	}

	os.Exit(1)
}

func _main(ctx context.Context, buildInfo models.BuildInformation,
	args []string, logger logging.ParentLogger, configReader config.Reader) error {
	if health.IsClientMode(args) {
		// Running the program in a separate instance through the Docker
		// built-in healthcheck, in an ephemeral fashion to query the
		// long running instance of the program about its status
		client := health.NewClient()
		return client.Query(ctx)
	}
	fmt.Println(splash.Splash(buildInfo))

	const clientTimeout = 15 * time.Second
	client := &http.Client{Timeout: clientTimeout}

	settings, err := configReader.ReadSettings()
	if err != nil {
		return err
	}
	logger = logger.NewChild(logging.Settings{
		Level: settings.LogLevel,
	})
	logger.Info("Settings summary:\n" + settings.String())

	const healthServerAddr = "127.0.0.1:9999"
	healthServer := health.NewServer(healthServerAddr,
		logger.NewChild(logging.Settings{Prefix: "healthcheck server: "}),
		health.IsHealthy)
	healthServerHandler, healthServerCtx, healthServerDone := goshutdown.NewGoRoutineHandler(
		"health server", goshutdown.GoRoutineSettings{})
	go healthServer.Run(healthServerCtx, healthServerDone)

	localIP := net.IP{127, 0, 0, 1}
	logger.Info("using DNS address %s internally", localIP.String())
	nameserver.UseDNSInternally(localIP) // use the DoT/DoH server

	dnsServerHandler, dnsServerCtx, dnsServerDone := goshutdown.NewGoRoutineHandler(
		"dns server", goshutdown.GoRoutineSettings{})
	crashed := make(chan error)
	go runLoop(dnsServerCtx, dnsServerDone, settings, logger, client, crashed)

	group := goshutdown.NewGroupHandler("", goshutdown.GroupSettings{})
	group.Add(healthServerHandler, dnsServerHandler)

	select {
	case <-ctx.Done():
	case err := <-crashed:
		logger.Error(err)
	}

	return group.Shutdown(context.Background())
}

func runLoop(ctx context.Context, dnsServerDone chan<- struct{}, settings config.Settings,
	logger logging.Logger, client *http.Client, crashed chan<- error,
) {
	defer close(dnsServerDone)
	timer := time.NewTimer(time.Hour)

	firstRun := true

	var (
		serverCtx    context.Context
		serverCancel context.CancelFunc
		waitError    chan error
	)

	for {
		timer.Stop()
		if settings.UpdatePeriod > 0 {
			timer.Reset(settings.UpdatePeriod)
		}

		serverSettings := settings.DoT

		if !firstRun {
			logger.Info("downloading and building DNS block lists")
			blacklistBuilder := blacklist.NewBuilder(client)
			blockedHostnames, blockedIPs, blockedIPPrefixes, errs :=
				blacklistBuilder.All(ctx, settings.Blacklist)
			for _, err := range errs {
				logger.Warn(err)
			}
			logger.Info("%d hostnames blocked overall", len(blockedHostnames))
			logger.Info("%d IP addresses blocked overall", len(blockedIPs))
			logger.Info("%d IP networks blocked overall", len(blockedIPPrefixes))
			serverSettings.Blacklist.IPs = blockedIPs
			serverSettings.Blacklist.IPPrefixes = blockedIPPrefixes
			serverSettings.Blacklist.BlockHostnames(blockedHostnames)

			serverCancel()
			<-waitError
			close(waitError)
		}
		serverCtx, serverCancel = context.WithCancel(ctx)

		var server models.Server
		switch settings.UpstreamType {
		case config.DoT:
			server = dot.NewServer(serverCtx, logger, serverSettings)
		case config.DoH:
			server = doh.NewServer(serverCtx, logger, settings.DoH)
		}

		logger.Info("starting DNS server")
		waitError = make(chan error)
		go server.Run(serverCtx, waitError)

		if settings.CheckDNS {
			if err := check.WaitForDNS(ctx, net.DefaultResolver); err != nil {
				crashed <- err
				serverCancel()
				return
			}
		}

		if firstRun {
			logger.Info("restarting DNS server the first time to get updated files")
			firstRun = false
			continue
		}

		select {
		case <-timer.C:
			logger.Info("planned periodic restart of DNS server")
		case <-ctx.Done():
			logger.Warn("exiting DNS server run loop (" + ctx.Err().Error() + ")")
			if !timer.Stop() {
				<-timer.C
			}
			if err := <-waitError; err != nil {
				logger.Error(err.Error())
			}
			close(waitError)
			serverCancel()
			return

		case waitErr := <-waitError:
			close(waitError)
			if !timer.Stop() {
				<-timer.C
			}
			serverCancel()
			crashed <- waitErr
			return
		}
	}
}
