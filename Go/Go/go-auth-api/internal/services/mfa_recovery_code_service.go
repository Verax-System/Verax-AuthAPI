package services

import (
	// IMPORT CORRIGIDO/ADICIONADO
	"errors"
	"go-auth-api/internal/database"
	"go-auth-api/internal/models"
	"log"

	"gorm.io/gorm"
)

// CreateRecoveryCodes gera novos códigos, apaga os antigos e guarda os hashes.
// Retorna os códigos em texto simples e um erro, se ocorrer.
func CreateRecoveryCodes(userID uint) ([]string, error) {
	db := database.DB
	// Gera os códigos ANTES da transação para poder retorná-los
	plainCodes := GeneratePlainRecoveryCodes() // Função de auth_service.go

	err := db.Transaction(func(tx *gorm.DB) error {
		// 1. Apagar códigos antigos
		if err := tx.Where("user_id = ?", userID).Delete(&models.MFARecoveryCode{}).Error; err != nil {
			log.Printf("Erro DB ao apagar códigos de recuperação antigos para user ID %d: %v", userID, err)
			return err // Rollback
		}

		// 2. Criar hashes e objetos DB a partir dos códigos já gerados
		dbCodes := make([]models.MFARecoveryCode, len(plainCodes))
		for i, code := range plainCodes {
			hashedCode, errHash := HashRecoveryCode(code) // Função de auth_service.go
			if errHash != nil {
				log.Printf("Erro ao fazer hash do código de recuperação %d para user ID %d: %v", i+1, userID, errHash)
				return errHash // Rollback
			}
			dbCodes[i] = models.MFARecoveryCode{
				UserID:     userID,
				HashedCode: hashedCode,
				IsUsed:     false,
			}
		}

		// 3. Inserir novos códigos
		if err := tx.Create(&dbCodes).Error; err != nil {
			log.Printf("Erro DB ao inserir novos códigos de recuperação para user ID %d: %v", userID, err)
			return err // Rollback
		}

		log.Printf("Gerados %d novos códigos de recuperação para user ID %d", len(plainCodes), userID)
		return nil // Commit
	})

	if err != nil {
		return nil, err // Retorna erro da transação
	}

	// 4. Retornar os códigos em texto simples (que foram gerados antes da transação)
	return plainCodes, nil
}

// DeleteAllRecoveryCodesForUser apaga todos os códigos de um utilizador.
func DeleteAllRecoveryCodesForUser(userID uint) (int64, error) {
	db := database.DB
	result := db.Where("user_id = ?", userID).Delete(&models.MFARecoveryCode{})
	if result.Error != nil {
		log.Printf("Erro DB ao apagar todos os códigos de recuperação para user ID %d: %v", userID, result.Error)
		return 0, result.Error
	}
	return result.RowsAffected, nil
}

// GetValidRecoveryCode verifica se um código em texto simples é válido e não usado.
// Retorna o objeto do código do DB se for válido.
func GetValidRecoveryCode(userID uint, plainCode string) (*models.MFARecoveryCode, error) {
	db := database.DB
	var codes []models.MFARecoveryCode
	// Buscar todos os códigos não usados
	err := db.Where("user_id = ? AND is_used = ?", userID, false).Find(&codes).Error
	if err != nil {
		log.Printf("Erro DB ao buscar códigos de recuperação não usados para user ID %d: %v", userID, err)
		return nil, errors.New("database error fetching recovery codes") // Usar errors.New
	}

	// Iterar e verificar o hash
	for _, dbCode := range codes {
		if VerifyRecoveryCode(plainCode, dbCode.HashedCode) { // Função de auth_service.go
			return &dbCode, nil // Encontrado e válido
		}
	}

	// Não encontrado ou inválido
	return nil, errors.New("invalid or used recovery code") // Usar errors.New
}

// MarkRecoveryCodeAsUsed marca um código específico como usado.
func MarkRecoveryCodeAsUsed(dbCode *models.MFARecoveryCode) error {
	db := database.DB
	dbCode.IsUsed = true
	if err := db.Save(dbCode).Error; err != nil {
		log.Printf("Erro DB ao marcar código de recuperação ID %d como usado: %v", dbCode.ID, err)
		return errors.New("database error updating recovery code") // Usar errors.New
	}
	return nil
}