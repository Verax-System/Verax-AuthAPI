package services

import (
	"errors"
	"fmt" // Para formatar mensagens de erro
	"go-auth-api/internal/config"
	"go-auth-api/internal/database"
	"go-auth-api/internal/models"
	"log" // Para logs
	"time"

	"gorm.io/gorm"
)

// Erro customizado para conta bloqueada (já existente)
var ErrAccountLocked = errors.New("account locked")

// AuthenticateUser (porta de crud_user.authenticate)
// (Código existente... sem alterações)
func AuthenticateUser(email, password string) (*models.User, error) {
	db := database.DB
	var user models.User

	// 1. Encontrar utilizador
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		// Não retorna "utilizador não encontrado" para evitar enumeração de utilizadores
		return nil, errors.New("incorrect email or password")
	}

	// 2. Verificar se a conta é OAuth (sem senha)
	if user.HashedPassword == nil || *user.HashedPassword == "" {
		log.Printf("Aviso: Tentativa de login com senha para conta OAuth: %s", email)
		return nil, errors.New("incorrect email or password") // Mesma mensagem genérica
	}


	// 3. Verificar se está bloqueado (Account Lockout)
	now := time.Now().UTC()
	if user.LockedUntil != nil && user.LockedUntil.After(now) {
		log.Printf("Aviso: Tentativa de login para conta bloqueada: %s", email)
		// Retorna o erro customizado com informação de tempo
		return nil, fmt.Errorf("%w: Try again in %v minute(s)", ErrAccountLocked, int(user.LockedUntil.Sub(now).Minutes())+1)
	}

	// 4. Verificar senha
	if !VerifyPassword(password, *user.HashedPassword) {
		// Senha incorreta, atualizar contador de falhas
		user.FailedLoginAttempts++
		cfg := config.AppConfig // Buscar a configuração

		if user.FailedLoginAttempts >= cfg.MaxFailedLogins {
			// Bloquear a conta
			lockDuration := time.Duration(cfg.LockoutMinutes) * time.Minute
			lockedUntilTime := now.Add(lockDuration)
			user.LockedUntil = &lockedUntilTime
			user.FailedLoginAttempts = 0 // Resetar contador após bloquear
			log.Printf("CONTA BLOQUEADA: %s por %d minutos.", email, cfg.LockoutMinutes)
		}

		// Salvar as alterações (contador ou bloqueio)
		if err := db.Save(&user).Error; err != nil {
			// Logar o erro, mas ainda retornar senha incorreta para o utilizador
			log.Printf("Erro ao salvar falha de login para %s: %v", email, err)
		}
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
		if err := db.Save(&user).Error; err != nil {
			log.Printf("Erro ao resetar falhas de login para %s: %v", email, err)
			// Não bloquear o login por causa disso, apenas logar
		}
	}

	return &user, nil
}

// SetPendingOTPSecret guarda temporariamente o segredo OTP no utilizador antes da confirmação.
func SetPendingOTPSecret(user *models.User, otpSecret string) error {
	if user.IsMfaEnabled {
		return errors.New("MFA is already enabled")
	}
	if otpSecret == "" {
		return errors.New("OTP secret cannot be empty")
	}
	db := database.DB
	user.OtpSecret = &otpSecret
	if err := db.Save(user).Error; err != nil {
		log.Printf("Erro DB ao salvar OTP secret pendente para user ID %d: %v", user.ID, err)
		return errors.New("database error saving pending OTP secret")
	}
	log.Printf("OTP secret pendente salvo para %s", user.Email)
	return nil
}

// ConfirmMFAEnable verifica o primeiro código OTP, marca MFA como ativo e gera códigos de recuperação.
// Retorna os códigos de recuperação em texto simples ou um erro.
func ConfirmMFAEnable(user *models.User, otpCode string) ([]string, error) {
	if user.IsMfaEnabled {
		return nil, errors.New("MFA is already enabled")
	}
	if user.OtpSecret == nil || *user.OtpSecret == "" {
		return nil, errors.New("MFA setup was not initiated (no pending secret)")
	}

	// Validar o código OTP
	if !ValidateOTP(*user.OtpSecret, otpCode) { // Função de auth_service.go
		log.Printf("Tentativa falha de confirmar MFA para %s: Código OTP inválido.", user.Email)
		return nil, errors.New("invalid OTP code")
	}

	// Marcar como ativo no DB
	db := database.DB
	user.IsMfaEnabled = true
	// O OtpSecret já está correto, não precisa mudar

	if err := db.Save(user).Error; err != nil {
		log.Printf("Erro DB ao marcar IsMfaEnabled para user ID %d: %v", user.ID, err)
		return nil, errors.New("database error enabling MFA")
	}

	// Gerar e guardar códigos de recuperação (usando o novo serviço)
	plainRecoveryCodes, errRec := CreateRecoveryCodes(user.ID)
	if errRec != nil {
		// O MFA foi ativado, mas falhou ao gerar códigos. Logar erro crítico.
		log.Printf("ERRO CRÍTICO: MFA ativado para user ID %d, mas falhou ao gerar/salvar códigos de recuperação: %v", user.ID, errRec)
		// Retornar um erro genérico para o utilizador, mas manter MFA ativo
		return nil, errors.New("MFA enabled, but failed to generate recovery codes. Contact support.")
	}

	log.Printf("MFA habilitado e confirmado com sucesso para %s", user.Email)
	return plainRecoveryCodes, nil
}

// DisableMFA verifica o código OTP atual, desmarca MFA como ativo e apaga segredo/códigos.
func DisableMFA(user *models.User, otpCode string) error {
	if !user.IsMfaEnabled {
		return errors.New("MFA is not enabled")
	}
	if user.OtpSecret == nil || *user.OtpSecret == "" {
		// Estado inconsistente, mas vamos tentar desativar mesmo assim
		log.Printf("AVISO: Tentando desabilitar MFA para user ID %d, mas OtpSecret está vazio.", user.ID)
		// return errors.New("OTP secret is missing, cannot verify code to disable")
	}

	// Validar o código OTP, SE houver segredo
	if user.OtpSecret != nil && *user.OtpSecret != "" {
		if !ValidateOTP(*user.OtpSecret, otpCode) { // Função de auth_service.go
			log.Printf("Tentativa falha de desabilitar MFA para %s: Código OTP inválido.", user.Email)
			return errors.New("invalid OTP code")
		}
	}


	// Desativar no DB
	db := database.DB
	user.IsMfaEnabled = false
	user.OtpSecret = nil // Limpar o segredo

	if err := db.Save(user).Error; err != nil {
		log.Printf("Erro DB ao desmarcar IsMfaEnabled para user ID %d: %v", user.ID, err)
		return errors.New("database error disabling MFA")
	}

	// Apagar códigos de recuperação (usando o novo serviço)
	deletedCount, errDel := DeleteAllRecoveryCodesForUser(user.ID)
	if errDel != nil {
		// MFA foi desativado, mas falhou ao apagar códigos. Logar erro.
		log.Printf("ERRO: MFA desativado para user ID %d, mas falhou ao apagar códigos de recuperação: %v", user.ID, errDel)
		// Não retornar erro para o utilizador aqui, a desativação principal funcionou
	} else {
		log.Printf("MFA desabilitado. Apagados %d códigos de recuperação para user ID %d.", deletedCount, user.ID)
	}


	log.Printf("MFA desabilitado com sucesso para %s", user.Email)
	return nil
}

// GetOrCreateByEmailOAuth (porta de crud_user.get_or_create_by_email_oauth)
// (Código existente... sem alterações)
func GetOrCreateByEmailOAuth(email, fullName string) (*models.User, error) {
	db := database.DB
	var user models.User

	// 1. Tentar encontrar
	if err := db.Where("email = ?", email).First(&user).Error; err == nil {
		// Utilizador encontrado
		// Opcional: Atualizar nome se estiver vazio
		if (user.FullName == nil || *user.FullName == "") && fullName != "" {
			user.FullName = &fullName
			db.Save(&user) // Salva a atualização do nome
		}
		return &user, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		// Erro real do DB
		log.Printf("Erro DB ao buscar utilizador OAuth (%s): %v", email, err)
		return nil, err
	}

	// 2. Não encontrado, criar
	log.Printf("Criando novo utilizador via OAuth para: %s", email)
	newUser := models.User{
		Email:          email,
		FullName:       &fullName,
		HashedPassword: nil, // Sem senha
		IsActive:       true, // Ativo por padrão
		IsVerified:     true, // Verificado (confiamos no OAuth)
		CustomClaims:   []byte("{}"), // Default claims
	}

	if err := db.Create(&newUser).Error; err != nil {
		log.Printf("Erro DB ao criar utilizador OAuth (%s): %v", email, err)
		return nil, err
	}

	return &newUser, nil
}


// --- FUNÇÕES PARA RESET DE SENHA ---

// GeneratePasswordResetToken (porta de crud_user.generate_password_reset_token)
func GeneratePasswordResetToken(user *models.User) (string, error) {
	db := database.DB

	// Criar o token JWT especial para reset
	tokenPlain, expiresAt, err := CreatePasswordResetToken(user.Email, user.ID)
	if err != nil {
		log.Printf("Erro ao criar token JWT de reset para user ID %d: %v", user.ID, err)
		return "", fmt.Errorf("could not generate reset token")
	}

	// Armazenar o hash e a expiração no utilizador
	tokenHash := HashToken(tokenPlain)
	user.ResetPasswordTokenHash = &tokenHash
	user.ResetPasswordTokenExpires = &expiresAt

	// Salvar no DB
	if err := db.Save(&user).Error; err != nil {
		log.Printf("Erro DB ao salvar token de reset para user ID %d: %v", user.ID, err)
		return "", fmt.Errorf("database error saving reset token")
	}

	log.Printf("Token de reset de senha gerado e salvo para %s", user.Email)
	return tokenPlain, nil // Retorna o token em texto simples para enviar por email
}

// GetUserByValidResetToken (porta de crud_user.get_user_by_reset_token)
func GetUserByValidResetToken(tokenPlain string) (*models.User, error) {
	db := database.DB

	// 1. Validar a estrutura JWT e expiração básica (ignora audience/issuer aqui)
	userIDStr, err := ValidatePasswordResetToken(tokenPlain)
	if err != nil {
		// Logar o erro JWT pode ser útil, mas retorna erro genérico
		log.Printf("Falha na validação JWT do token de reset: %v", err)
		return nil, errors.New("invalid or expired reset token")
	}

	// 2. Calcular o hash para procurar no DB
	tokenHash := HashToken(tokenPlain)
	now := time.Now().UTC()
	var user models.User

	// 3. Procurar no DB pelo hash, expiração e se utilizador está ativo
	err = db.Where(
		"reset_password_token_hash = ? AND reset_password_token_expires > ? AND is_active = ?",
		tokenHash, now, true,
	).First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid, expired, or already used reset token")
		}
		log.Printf("Erro DB ao buscar utilizador por token de reset (hash: %s...): %v", tokenHash[:10], err)
		return nil, fmt.Errorf("database error validating reset token")
	}

	// 4. Verificar se o ID do utilizador encontrado corresponde ao ID no token (segurança extra)
	if fmt.Sprint(user.ID) != userIDStr {
		log.Printf("ALERTA: Token de reset válido encontrado no DB (hash: %s...), mas ID do utilizador (%d) não corresponde ao Subject do JWT (%s)", tokenHash[:10], user.ID, userIDStr)
		return nil, errors.New("token mismatch") // Ou erro genérico
	}

	return &user, nil
}


// ResetPassword (porta de crud_user.reset_password)
func ResetPassword(user *models.User, newPassword string) error {
	db := database.DB

	// 1. Hash da nova senha
	// TODO: Adicionar validação de força da senha aqui
	newHashedPassword, err := HashPassword(newPassword)
	if err != nil {
		log.Printf("Erro ao fazer hash da nova senha (reset) para user ID %d: %v", user.ID, err)
		return fmt.Errorf("error processing new password")
	}
	user.HashedPassword = &newHashedPassword

	// 2. Limpar campos de reset e lockout
	user.ResetPasswordTokenHash = nil
	user.ResetPasswordTokenExpires = nil
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	user.IsActive = true // Garante que está ativo

	// 3. Revogar todos os Refresh Tokens (sessões) existentes para este utilizador
	// AGORA CHAMANDO A FUNÇÃO DO OUTRO SERVICE
	revokedCount, errRevoke := RevokeAllRefreshTokensForUser(user.ID, "") // Passar "" para não excluir nenhum
	if errRevoke != nil {
		// Logar o erro mas não impedir o reset da senha
		log.Printf("AVISO: Falha ao revogar refresh tokens para user ID %d após reset de senha: %v", user.ID, errRevoke)
	} else {
		log.Printf("Revogados %d refresh tokens para user ID %d após reset de senha.", revokedCount, user.ID)
	}


	// 4. Salvar o utilizador com a nova senha e campos limpos
	if err := db.Save(&user).Error; err != nil {
		log.Printf("Erro DB ao salvar nova senha para user ID %d: %v", user.ID, err)
		return fmt.Errorf("database error updating password")
	}

	log.Printf("Senha redefinida com sucesso para %s", user.Email)
	return nil
}

// --- FIM FUNÇÕES DE RESET ---