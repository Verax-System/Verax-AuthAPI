package services

import (
	"errors"
	"go-auth-api/internal/config"
	"go-auth-api/internal/database"
	"go-auth-api/internal/models"
	"time"

	"gorm.io/gorm"
)

// Erro customizado para conta bloqueada
var ErrAccountLocked = errors.New("account locked")

// AuthenticateUser (porta de crud_user.authenticate)
func AuthenticateUser(email, password string) (*models.User, error) {
	db := database.DB
	var user models.User

	// 1. Encontrar usuário
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		// Não retorna "usuário não encontrado" para evitar enumeração de usuários
		return nil, errors.New("incorrect email or password")
	}

	// 2. Verificar se a conta é OAuth (sem senha)
	if user.HashedPassword == nil || *user.HashedPassword == "" {
		log.Printf("Aviso: Tentativa de login com senha para conta OAuth: %s", email)
		return nil, errors.New("incorrect email or password")
	}

	// 3. Verificar se está bloqueado (Account Lockout)
	now := time.Now().UTC()
	if user.LockedUntil != nil && user.LockedUntil.After(now) {
		log.Printf("Aviso: Tentativa de login para conta bloqueada: %s", email)
		// Retorna o erro customizado
		return nil, fmt.Errorf("%w: Try again in %v minute(s)", ErrAccountLocked, int(user.LockedUntil.Sub(now).Minutes())+1)
	}

	// 4. Verificar senha
	if !VerifyPassword(password, *user.HashedPassword) {
		// Senha incorreta, atualizar contador de falhas
		user.FailedLoginAttempts++
		cfg := config.AppConfig
		
		if user.FailedLoginAttempts >= cfg.MaxFailedLogins {
			// Bloquear a conta
			lockDuration := time.Duration(cfg.LockoutMinutes) * time.Minute
			lockedUntilTime := now.Add(lockDuration)
			user.LockedUntil = &lockedUntilTime
			user.FailedLoginAttempts = 0 // Resetar contador após bloquear
			log.Printf("CONTA BLOQUEADA: %s por %d minutos.", email, cfg.LockoutMinutes)
		}
		
		db.Save(&user)
		return nil, errors.New("incorrect email or password")
	}

	// 5. Verificar se está ativo/verificado
	if !user.IsActive || !user.IsVerified {
		log.Printf("Aviso: Login falhou (senha correta) para email não ativo/verificado: %s", email)
		return nil, errors.New("account inactive or email not verified")
	}

	// 6. Sucesso! Resetar contadores de falha se houver
	if user.FailedLoginAttempts > 0 || user.LockedUntil != nil {
		user.FailedLoginAttempts = 0
		user.LockedUntil = nil
		db.Save(&user)
	}

	return &user, nil
}

// GetOrCreateByEmailOAuth (porta de crud_user.get_or_create_by_email_oauth)
func GetOrCreateByEmailOAuth(email, fullName string) (*models.User, error) {
	db := database.DB
	var user models.User

	// 1. Tentar encontrar
	if err := db.Where("email = ?", email).First(&user).Error; err == nil {
		// Usuário encontrado
		// Opcional: Atualizar nome se estiver vazio
		if (user.FullName == nil || *user.FullName == "") && fullName != "" {
			user.FullName = &fullName
			db.Save(&user)
		}
		return &user, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		// Erro real do DB
		return nil, err
	}

	// 2. Não encontrado, criar
	log.Printf("Criando novo usuário via OAuth para: %s", email)
	newUser := models.User{
		Email:          email,
		FullName:       &fullName,
		HashedPassword: nil, // Sem senha
		IsActive:       true, // Ativo por padrão
		IsVerified:     true, // Verificado (confiamos no OAuth)
		// CustomClaims pode ser definido como {} por padrão se desejado
	}

	if err := db.Create(&newUser).Error; err != nil {
		return nil, err
	}
	
	return &newUser, nil
}

// (Outras funções CRUD podem ser adicionadas aqui: GetUserByID, etc.)