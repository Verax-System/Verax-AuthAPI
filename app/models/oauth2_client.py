# auth_api/app/models/oauth2_client.py
from sqlalchemy import String, Text, Boolean, Integer, Index, JSON
from sqlalchemy.orm import Mapped, mapped_column
from typing import List, Optional

from app.db.base import Base

class OAuth2Client(Base):
    """
    Representa uma aplicação cliente registrada que pode usar
    esta API como um Provedor de Identidade OIDC/OAuth2.
    """
    __tablename__ = "oauth2_clients"

    id: Mapped[int] = mapped_column(primary_key=True)
    # client_id e client_secret são gerados por nós e fornecidos à aplicação cliente
    client_id: Mapped[str] = mapped_column(String(48), unique=True, index=True, nullable=False)
    client_secret_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True) # Hash do secret, se confidencial

    # Metadados do cliente (seguindo RFC7591)
    client_name: Mapped[Optional[str]] = mapped_column(String(120))
    # Lista de URIs para onde podemos redirecionar o utilizador após o login
    redirect_uris_str: Mapped[Optional[Text]] = mapped_column(Text) # Armazenado como texto separado por espaço
    # Lista de scopes que este cliente pode solicitar (ex: "openid profile email")
    scope_str: Mapped[Optional[Text]] = mapped_column(Text, default="openid profile email", nullable=False) # Armazenado como texto separado por espaço
    # Tipos de resposta permitidos (ex: "code", "token id_token")
    response_types_str: Mapped[Optional[Text]] = mapped_column(Text, default="code", nullable=False) # Armazenado como texto separado por espaço
    # Tipos de grant permitidos (ex: "authorization_code", "refresh_token")
    grant_types_str: Mapped[Optional[Text]] = mapped_column(Text, default="authorization_code refresh_token", nullable=False) # Armazenado como texto separado por espaço
    # Método de autenticação do endpoint de token (ex: "client_secret_basic", "client_secret_post", "none")
    token_endpoint_auth_method: Mapped[Optional[str]] = mapped_column(String(120), default="client_secret_basic")

    # Campos específicos do Authlib para conveniência (podem ser derivados dos _str)
    @property
    def redirect_uris(self) -> List[str]:
        return self.redirect_uris_str.split() if self.redirect_uris_str else []

    @property
    def scope(self) -> str:
        return self.scope_str or "" # Authlib espera uma string

    @property
    def response_types(self) -> List[str]:
        return self.response_types_str.split() if self.response_types_str else []

    @property
    def grant_types(self) -> List[str]:
        return self.grant_types_str.split() if self.grant_types_str else []

    # -- Métodos Helper exigidos/úteis para Authlib --
    def get_client_id(self) -> str:
        return self.client_id

    def get_default_redirect_uri(self) -> Optional[str]:
        if self.redirect_uris:
            return self.redirect_uris[0]
        return None

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        return redirect_uri in self.redirect_uris

    def has_client_secret(self) -> bool:
        return bool(self.client_secret_hash)

    def check_client_secret(self, client_secret: str) -> bool:
        # Implementar comparação de hash segura aqui!
        # Ex: return pwd_context.verify(client_secret, self.client_secret_hash)
        # Por agora, faremos uma comparação simples (NÃO SEGURO PARA PRODUÇÃO)
        # Você precisará importar e usar o seu 'pwd_context' de security.py
        from app.core.security import pwd_context # Import local temporário
        if not self.client_secret_hash:
            return False
        return pwd_context.verify(client_secret, self.client_secret_hash)


    def check_response_type(self, response_type: str) -> bool:
        return response_type in self.response_types

    def check_grant_type(self, grant_type: str) -> bool:
        return grant_type in self.grant_types

    def check_scope(self, scope: str) -> bool:
        # Verifica se todos os scopes pedidos estão nos scopes permitidos
        requested_scopes = set(scope.split())
        allowed_scopes = set(self.scope.split())
        return requested_scopes.issubset(allowed_scopes)