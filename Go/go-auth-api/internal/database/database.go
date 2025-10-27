package database

import (
	"go-auth-api/internal/config"
	"go-auth-api/internal/models"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDatabase() {
	var err error
	dsn := config.AppConfig.DatabaseURL

	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Falha ao conectar ao banco de dados: %v", err)
	}

	log.Println("Iniciando migração automática do banco de dados (AutoMigrate)...")
	// Isso substitui o Alembic, criando/atualizando tabelas conforme os models
	err = DB.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.MFARecoveryCode{},
		&models.TrustedDevice{},
	)
	if err != nil {
		log.Fatalf("Falha ao migrar o banco de dados: %v", err)
	}
	log.Println("Banco de dados migrado com sucesso.")
}