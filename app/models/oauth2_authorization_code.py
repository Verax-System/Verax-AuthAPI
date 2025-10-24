# auth_api/app/models/oauth2_authorization_code.py
from sqlalchemy import String, Text, Integer, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Optional
from app.db.base import Base

class OAuth2AuthorizationCode(Base):
    """
    Armazena temporariamente os códigos de autorização gerados
    durante o fluxo OIDC Authorization Code.
    """
    __tablename__ = "oauth2_authorization_codes"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    client_id: Mapped[str] = mapped_column(String(48), nullable=False) # FK para oauth2_clients.client_id seria melhor
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    redirect_uri: Mapped[Optional[Text]] = mapped_column(Text)
    response_type: Mapped[Optional[Text]] = mapped_column(Text)
    scope: Mapped[Optional[Text]] = mapped_column(Text)
    auth_time: Mapped[int] = mapped_column(Integer, nullable=False) # Timestamp UNIX

    # Campos OIDC adicionais
    nonce: Mapped[Optional[str]] = mapped_column(String(120))
    code_challenge: Mapped[Optional[str]] = mapped_column(String(128)) # Para PKCE
    code_challenge_method: Mapped[Optional[str]] = mapped_column(String(48)) # Para PKCE (ex: "S256")

    user: Mapped["User"] = relationship() # type: ignore

    def is_expired(self) -> bool:
        # Lógica para verificar se o código expirou (ex: auth_time + 60 segundos)
        import time
        return time.time() > self.auth_time + 60 # Exemplo: expira em 60 segundos

    def get_redirect_uri(self) -> Optional[str]:
        return self.redirect_uri

    def get_scope(self) -> Optional[str]:
        return self.scope

    def get_auth_time(self) -> int:
        return self.auth_time