package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/lumen-paste/lumen/config"
	"github.com/lumen-paste/lumen/database"
	"github.com/lumen-paste/lumen/handlers"
	"github.com/lumen-paste/lumen/middleware"
)

func main() {
	// Load .env file if present; falls back to environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables and defaults")
	}

	cfg := config.Load()

	if err := database.Initialize(cfg.DatabasePath); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	var r *gin.Engine
	if cfg.Environment == "production" {
		r = gin.New()
		r.Use(gin.Recovery())
	} else {
		r = gin.Default()
	}

	// Trust specific proxies for accurate client IPs (e.g. TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8)
	if len(cfg.TrustedProxies) > 0 {
		r.SetTrustedProxies(cfg.TrustedProxies)
	} else {
		r.SetTrustedProxies(nil)
	}

	// Template functions used in HTML templates
	r.SetFuncMap(template.FuncMap{
		"safeHTML":   func(s string) template.HTML { return template.HTML(s) },
		"splitLines": func(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") },
		"add":        func(a, b int) int { return a + b },
	})

	// Resolve template/static paths relative to both CWD (dev) and binary location (deploy)
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	execDir := filepath.Dir(execPath)

	templatePaths := []string{
		"./templates/*.html",
		filepath.Join(execDir, "templates", "*.html"),
	}
	templatesLoaded := false
	for _, path := range templatePaths {
		if matches, _ := filepath.Glob(path); len(matches) > 0 {
			r.LoadHTMLGlob(path)
			templatesLoaded = true
			log.Printf("Loaded templates from: %s", path)
			break
		}
	}
	if !templatesLoaded {
		log.Fatal("Failed to load templates from any path")
	}

	for _, path := range []string{"./static", filepath.Join(execDir, "static")} {
		if _, err := os.Stat(path); err == nil {
			r.Static("/static", path)
			log.Printf("Serving static files from: %s", path)
			break
		}
	}

	// Global middleware: security headers, CSRF, request size limit
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.CSRF())
	r.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, cfg.MaxPasteSize+4096)
		c.Next()
	})

	// Routes — creation is rate-limited separately from viewing
	homeGroup := r.Group("/")
	homeGroup.Use(middleware.CreateRateLimit(cfg.CreateRateLimit, cfg.RateWindow))
	{
		homeGroup.GET("/", handlers.Home)
		homeGroup.POST("/", handlers.CreatePaste(cfg))
	}

	pasteGroup := r.Group("/p")
	pasteGroup.Use(middleware.ViewRateLimit(cfg.ViewRateLimit, cfg.RateWindow))
	{
		pasteGroup.GET("/:id", handlers.ViewPaste)
		pasteGroup.POST("/:id/unlock", handlers.UnlockPaste)
		pasteGroup.GET("/:id/raw", handlers.RawPaste)
		pasteGroup.GET("/:id/fork", handlers.ForkPaste)
		pasteGroup.GET("/:id/download", handlers.DownloadPaste)
		pasteGroup.GET("/:id/delete/:token", handlers.ConfirmDelete)
		pasteGroup.POST("/:id/delete/:token", handlers.ExecuteDelete)
	}

	r.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusNotFound, "404.html", gin.H{
			"Title": "Page Not Found - Lumen",
		})
	})

	// HTTP server with timeouts to prevent slow-loris and resource exhaustion
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	go func() {
		log.Printf("Starting Lumen on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Graceful shutdown: wait for SIGINT/SIGTERM, then drain in-flight requests
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Server exited gracefully")
}
