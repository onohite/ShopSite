package app

import (
	"Gateway/internal/config"
	"Gateway/internal/routes"
	"Gateway/internal/service"
	"context"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// @title EchoProject REST API
// @version 1.0
// @description Server for CSU and self-improvement

// @host localhost:80
// @BasePath /api/v1/

// Run initializes whole application.
func Run() {
	cfg := config.Init()
	baseContext := context.Background()

	ctx, cancel := context.WithCancel(baseContext)
	defer cancel()

	services, err := service.InitService(ctx, cfg)
	if err != nil {
		log.Panic(err)
	}

	handler := routes.NewHandler(services, cfg)

	go func(srv *echo.Echo) {
		if err := srv.Start(fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)); err != nil {
			log.Fatal(err.Error())
		}
	}(handler.Init(cfg))

	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Warn("Shutting down server...")
	time.Sleep(time.Second * 5)
}
