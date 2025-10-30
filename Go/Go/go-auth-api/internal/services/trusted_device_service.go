package services

import (
	"errors"
	"fmt"
	"go-auth-api/internal/database"
	"go-auth-api/internal/models"
	"log"
	"time"

	"gorm.io/gorm"
)

// GetTrustedDeviceByTokenHash finds a trusted device by its token hash
// and updates its last_used_at timestamp.
func GetTrustedDeviceByTokenHash(tokenHash string) (*models.TrustedDevice, error) {
	db := database.DB
	var device models.TrustedDevice

	err := db.Where("device_token_hash = ?", tokenHash).First(&device).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("trusted device not found")
		}
		log.Printf("Erro DB ao buscar trusted device por hash (%s...): %v", tokenHash[:10], err)
		return nil, errors.New("database error fetching trusted device")
	}

	// Update last_used_at
	now := time.Now().UTC()
	if err := db.Model(&device).Update("last_used_at", &now).Error; err != nil {
		// Log the error but don't fail the operation
		log.Printf("Erro ao atualizar last_used_at para trusted device ID %d: %v", device.ID, err)
	}

	return &device, nil
}

// GetTrustedDevicesForUser retrieves all trusted devices for a given user ID.
func GetTrustedDevicesForUser(userID uint) ([]models.TrustedDevice, error) {
	db := database.DB
	var devices []models.TrustedDevice

	err := db.Where("user_id = ?", userID).Order("last_used_at DESC").Find(&devices).Error
	if err != nil {
		log.Printf("Erro DB ao buscar trusted devices para user ID %d: %v", userID, err)
		return nil, errors.New("database error fetching trusted devices")
	}

	return devices, nil
}

// GetTrustedDeviceByIDForUser retrieves a specific trusted device by its ID,
// ensuring it belongs to the correct user.
func GetTrustedDeviceByIDForUser(deviceID uint, userID uint) (*models.TrustedDevice, error) {
	db := database.DB
	var device models.TrustedDevice

	err := db.Where("id = ? AND user_id = ?", deviceID, userID).First(&device).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("trusted device not found or does not belong to this user")
		}
		log.Printf("Erro DB ao buscar trusted device ID %d para user ID %d: %v", deviceID, userID, err)
		return nil, errors.New("database error fetching trusted device")
	}

	return &device, nil
}

// DeleteTrustedDevice removes a specific trusted device from the database.
func DeleteTrustedDevice(device *models.TrustedDevice) error {
	db := database.DB
	if err := db.Delete(device).Error; err != nil {
		log.Printf("Erro DB ao deletar trusted device ID %d para user ID %d: %v", device.ID, device.UserID, err)
		return fmt.Errorf("database error deleting trusted device")
	}
	log.Printf("Trusted device (ID: %d) removido para user ID %d", device.ID, device.UserID)
	return nil
}