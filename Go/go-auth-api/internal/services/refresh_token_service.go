package services

import (
	"errors" // Para erros
	"go-auth-api/internal/database"
	"go-auth-api/internal/models"
	"log" // Para logs
	"time"

	"gorm.io/gorm"
)

// RevokeAllRefreshTokensForUser revoga todos os tokens ativos de um utilizador.
// Retorna o número de tokens revogados e um erro, se ocorrer.
func RevokeAllRefreshTokensForUser(userID uint, excludeTokenHash string) (int64, error) {
	db := database.DB
	now := time.Now().UTC()

	query := db.Model(&models.RefreshToken{}).
		Where("user_id = ? AND is_revoked = ? AND expires_at > ?", userID, false, now)

	// Se um hash for fornecido para exclusão (ex: manter a sessão atual)
	if excludeTokenHash != "" {
		query = query.Where("token_hash != ?", excludeTokenHash)
	}

	// Atualiza o campo is_revoked para true
	result := query.Update("is_revoked", true)

	if result.Error != nil {
		log.Printf("Erro DB ao revogar refresh tokens para user ID %d: %v", userID, result.Error)
		return 0, result.Error // Retorna o erro do GORM
	}

	return result.RowsAffected, nil // Retorna o número de linhas afetadas e nil erro
}

// GetValidRefreshTokenByHash busca um refresh token pelo seu hash,
// verificando se não está revogado e não expirou.
func GetValidRefreshTokenByHash(tokenHash string) (*models.RefreshToken, error) {
	db := database.DB
	now := time.Now().UTC()
	var dbToken models.RefreshToken

	err := db.Where(
		"token_hash = ? AND is_revoked = ? AND expires_at > ?",
		tokenHash, false, now,
	).First(&dbToken).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("refresh token not found, revoked, or expired")
		}
		log.Printf("Erro DB ao buscar refresh token por hash (%s...): %v", tokenHash[:10], err)
		return nil, errors.New("database error validating refresh token")
	}

	return &dbToken, nil
}

// RevokeRefreshTokenByHash marca um refresh token específico como revogado, usando o hash.
// Retorna true se revogado com sucesso, false caso contrário (já revogado, não encontrado).
func RevokeRefreshTokenByHash(tokenHash string) (bool, error) {
	db := database.DB
	result := db.Model(&models.RefreshToken{}).
		Where("token_hash = ? AND is_revoked = ?", tokenHash, false).
		Update("is_revoked", true)

	if result.Error != nil {
		log.Printf("Erro DB ao revogar refresh token por hash (%s...): %v", tokenHash[:10], result.Error)
		return false, result.Error
	}

	return result.RowsAffected > 0, nil // Retorna true se alguma linha foi afetada
}

// PruneExpiredTokens (opcional, para limpeza periódica)
// Deleta tokens que já expiraram do banco de dados.
func PruneExpiredTokens() (int64, error) {
	db := database.DB
	now := time.Now().UTC()

	result := db.Where("expires_at <= ?", now).Delete(&models.RefreshToken{})

	if result.Error != nil {
		log.Printf("Erro DB ao limpar refresh tokens expirados: %v", result.Error)
		return 0, result.Error
	}
	if result.RowsAffected > 0 {
		log.Printf("Limpados %d refresh tokens expirados do banco de dados.", result.RowsAffected)
	}
	return result.RowsAffected, nil
}