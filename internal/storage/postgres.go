package storage

import (
	"errors"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"penkeeper/internal/model"
	"time"
)

// DB is a thin wrapper around *gorm.DB so we can pass it around.
type DB struct {
	*gorm.DB
}

// ErrForeignDB is returned when the database at DATABASE_URL was not made by
// penkeeper: its assessments table has a type column, which penkeeper's does
// not have. Penkeeper must not migrate or write another application's data.
var ErrForeignDB = errors.New("DATABASE_URL points at a database that penkeeper did not create")

// NewPostgres opens a connection, runs auto‑migration for the models we need,
// and returns the wrapper.
func NewPostgres(dsn string) (*DB, error) {
	// GORM's default logger, except that a lookup miss (e.g. an unknown login
	// email) is not logged and SQL is logged without its values, so request
	// data (control characters, credentials, tool output) never reaches the log.
	gormLog := logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{
		SlowThreshold:             200 * time.Millisecond,
		LogLevel:                  logger.Warn,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
		Colorful:                  true,
	})
	g, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormLog})
	if err != nil {
		return nil, fmt.Errorf("gorm open: %w", err)
	}

	// Bound the pool so a burst of slow requests queues for a connection
	// instead of exhausting PostgreSQL's max_connections (default 100,
	// shared with every other database on the cluster).
	sqlDB, err := g.DB()
	if err != nil {
		return nil, fmt.Errorf("gorm db: %w", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)

	if g.Migrator().HasColumn("assessments", "type") {
		return nil, ErrForeignDB
	}

	// Rename legacy tables/columns if they exist (engagements → assessments).
	migrateEngagementToAssessment(g)

	// Auto‑migrate the tables we use.
	if err := g.AutoMigrate(&model.User{}, &model.Assessment{}, &model.Host{}, &model.Port{}, &model.Credential{}, &model.Note{}, &model.Command{}, &model.ActivityLog{}, &model.ToolOutput{}, &model.PasswordResetToken{}); err != nil {
		return nil, fmt.Errorf("auto migrate: %w", err)
	}

	// Upgrade caveat: ports.service_edited and ports.info_edited are added as
	// false, because older databases (and bundles) keep no record of which
	// Service/Info values were typed by hand. Nmap imports may therefore still
	// replace values typed before the upgrade; only values typed afterwards
	// (or changed in Edit Port since) are protected.

	return &DB{DB: g}, nil
}

// migrateEngagementToAssessment renames the old "engagements" table and
// "engagement_id" column to "assessments" / "assessment_id" if they exist.
// Safe to run repeatedly — skips if already renamed.
func migrateEngagementToAssessment(g *gorm.DB) {
	// Rename table if old name exists
	if g.Migrator().HasTable("engagements") && !g.Migrator().HasTable("assessments") {
		if err := g.Exec("ALTER TABLE engagements RENAME TO assessments").Error; err != nil {
			log.Printf("migration: failed to rename engagements table: %v", err)
		} else {
			log.Println("migration: renamed table engagements → assessments")
		}
	}

	// Rename foreign key column in hosts if old column exists
	if g.Migrator().HasTable("hosts") && g.Migrator().HasColumn(&model.Host{}, "engagement_id") {
		if err := g.Exec("ALTER TABLE hosts RENAME COLUMN engagement_id TO assessment_id").Error; err != nil {
			log.Printf("migration: failed to rename engagement_id column: %v", err)
		} else {
			log.Println("migration: renamed column hosts.engagement_id → assessment_id")
		}
	}
}
