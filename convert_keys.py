import json
from authlib.jose import JsonWebKey
from cryptography.hazmat.primitives import serialization

# --- Configuração ---
PRIVATE_KEY_FILE = 'private_key.pem'
PUBLIC_KEY_FILE = 'public_key.pem'
OUTPUT_PRIVATE_JWK_FILE = 'private_jwk.json'
OUTPUT_PUBLIC_JWK_SET_FILE = 'public_jwk_set.json'
KEY_ID = 'verax-auth-oidc-key-1' # Um identificador único para esta chave

# --- Carregar Chave Privada PEM ---
try:
    with open(PRIVATE_KEY_FILE, 'rb') as f:
        private_pem = f.read()
    # Apenas verifica se pode ser carregada, não guarda o objeto cryptography
    serialization.load_pem_private_key(private_pem, password=None)
    print(f"Chave privada '{PRIVATE_KEY_FILE}' carregada com sucesso.")
except FileNotFoundError:
    print(f"ERRO: Ficheiro da chave privada '{PRIVATE_KEY_FILE}' não encontrado.")
    exit(1)
except Exception as e:
    print(f"ERRO ao carregar a chave privada: {e}")
    exit(1)

# --- Carregar Chave Pública PEM ---
try:
    with open(PUBLIC_KEY_FILE, 'rb') as f:
        public_pem = f.read()
    # Apenas verifica se pode ser carregada, não guarda o objeto cryptography
    serialization.load_pem_public_key(public_pem)
    print(f"Chave pública '{PUBLIC_KEY_FILE}' carregada com sucesso.")
except FileNotFoundError:
    print(f"ERRO: Ficheiro da chave pública '{PUBLIC_KEY_FILE}' não encontrado.")
    exit(1)
except Exception as e:
    print(f"ERRO ao carregar a chave pública: {e}")
    exit(1)

# --- Converter para JWK (com tratamento de erro) ---
# Inicializar variáveis para evitar NameError
private_jwk_dict = None
public_jwk_set = None
try:
    # Chave privada
    # Passar o conteúdo PEM bruto (bytes) diretamente
    private_jwk_obj = JsonWebKey.import_key(private_pem, {'use': 'sig'})
    private_jwk_dict = private_jwk_obj.as_dict(private=True) # Pedir o formato completo
    private_jwk_dict['kid'] = KEY_ID # Adicionar o Key ID

    # Chave pública (para o JWKSet)
    # Passar o conteúdo PEM bruto (bytes) diretamente
    public_jwk_obj = JsonWebKey.import_key(public_pem, {'use': 'sig'})
    public_jwk_dict = public_jwk_obj.as_dict(private=False) # Pedir apenas o formato público
    public_jwk_dict['kid'] = KEY_ID # Adicionar o Key ID
    public_jwk_set = {'keys': [public_jwk_dict]}

except Exception as e:
    print(f"ERRO durante a conversão das chaves PEM para JWK: {e}")
    exit(1) # Sair se a conversão falhar

# --- Salvar Ficheiros JSON ---
try:
    # Verificar se as variáveis foram realmente criadas antes de salvar
    if private_jwk_dict:
        with open(OUTPUT_PRIVATE_JWK_FILE, 'w') as f:
            json.dump(private_jwk_dict, f, indent=4)
        print(f"Chave privada JWK salva em '{OUTPUT_PRIVATE_JWK_FILE}'.")
    else:
        # Este else não deve ser atingido por causa do exit(1) acima, mas é uma segurança extra
        print("ERRO: Dicionário da chave privada JWK não foi definido.")
        exit(1)

    if public_jwk_set:
        with open(OUTPUT_PUBLIC_JWK_SET_FILE, 'w') as f:
            json.dump(public_jwk_set, f, indent=4)
        print(f"Conjunto de chaves públicas JWKSet salvo em '{OUTPUT_PUBLIC_JWK_SET_FILE}'.")
    else:
        # Este else não deve ser atingido
        print("ERRO: Conjunto de chaves públicas JWKSet não foi definido.")
        exit(1)

except Exception as e:
    print(f"ERRO ao salvar os ficheiros JWK: {e}")
    exit(1)

print("\nConversão concluída!")
print(f"IMPORTANTE: Proteja o ficheiro '{OUTPUT_PRIVATE_JWK_FILE}'!")